# Warden — état d'avancement

Warden est un EDR autonome pour workstations Linux, écrit en Rust. Ce
fichier existe pour reprendre le projet proprement après une coupure de
session — le lire en entier avant de continuer.

L'utilisateur a donné le feu vert pour travailler en autonomie complète
(core, agents, DAST, SAST, GUI, tests réels en conteneurs, YARA/Sigma,
tout) sans notifier chaque avancée dans le chat — un point d'étape complet
suffit. Priorité explicite : **finir tous les agents de détection + le core
d'abord, GUI ensuite, `install.sh` en tout dernier.**

## Règle absolue de workflow

**Rien ne compile ni ne s'exécute jamais sur l'hôte.** Le code est écrit et
édité ici, dans `/home/user/warden`, mais :
- **build** → uniquement dans le conteneur `warden-build:rockylinux`
- **run/test** → uniquement dans les conteneurs de test par distro

Commande de build de référence (3 volumes persistants à toujours monter
ensemble pour ne pas perdre rustup/clippy/le registry cargo entre les
runs) :
```
docker run --rm -v /home/user/warden:/build \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -v warden-cargo-home:/usr/local/cargo \
  -v warden-rustup-home:/usr/local/rustup \
  -w /build warden-build:rockylinux cargo build --release
```
Clippy (une fois par volume neuf) : `rustup component add clippy` puis
`cargo clippy --release --all-targets`.

## Architecture générale

Workspace Cargo à 4 crates :
- `warden-common` — types partagés (`DetectionEvent`, `Severity`, `Mode`),
  et les briques réutilisables par tout module de détection :
  `process::stop_then_kill`, `quarantine::Quarantine`,
  `response::handle_detection` (réponse avec PID, kill+quarantine),
  `response::handle_file_only_detection` (réponse SANS PID, quarantine
  seule — voir point 6 ci-dessous), `notify::Notifier`.
- `warden-ransomware` — détection ransomware par fanotify, porté et adapté
  de RansomShield (`/home/user/ransomshield`, projet séparé, jamais modifié
  par Warden).
- `warden-persistence` — détection de persistance par inotify (bashrc,
  cron, autostart XDG, unités systemd, sudoers, authorized_keys,
  ld.so.preload). Détails complets plus bas.
- `warden-core` — binaire `warden` : config TOML, résolution de
  l'utilisateur cible, orchestrateur multi-module, dispatcher d'events.

### Décisions d'architecture importantes (et pourquoi)

1. **Réponse synchrone dans le module détecteur, jamais via le channel
   async.** Un module qui a besoin d'agir vite (tuer un process, mettre en
   quarantaine) le fait directement dans son propre thread bloquant, puis
   construit un `DetectionEvent` envoyé au dispatcher *seulement* pour
   log/notif/historique futur. Un design où le module "proposerait" une
   action exécutée plus tard par le dispatcher via channel async a été
   rejeté : latence inacceptable face à une menace active.

2. **fanotify (ransomware) marque tout le mount, filtré en userspace.**
   `$HOME` d'une workstation est presque toujours sur la partition racine,
   donc `FAN_MARK_FILESYSTEM` watche tout `/`. On filtre en userspace
   (`fanotify_monitor::is_under_watch_dirs`) pour ne traiter que les events
   sous les dossiers réellement configurés (canonicalisés, `~` expansé
   manuellement puisque TOML n'est pas un shell).

3. **inotify (persistence) watche des DOSSIERS, jamais des fichiers
   directement.** De nombreux éditeurs sauvegardent en écrivant un fichier
   temporaire puis en le renommant à la place de l'original — ça remplace
   l'inode et invaliderait silencieusement un watch posé sur le fichier
   lui-même. On watche systématiquement le dossier parent (`$HOME`,
   `~/.ssh`, `/etc`, `/etc/cron.d`, etc.) et on filtre par nom de fichier
   côté userspace, exactement le même principe que le filtrage fanotify.

4. **Notification desktop via zbus, connexion explicite au bus de session
   de l'utilisateur cible** (`unix:path=/run/user/<uid>/bus`), jamais de
   découverte auto via `DBUS_SESSION_BUS_ADDRESS` (pointerait vers rien
   pour un service root). Testé : échoue proprement (log warn, pas de
   crash) sans session graphique — comportement attendu, pas encore
   revalidé avec un vrai DE simulé.

5. **`target_user` explicite en config, pas d'auto-détection.** Root n'a
   pas de `$HOME` personnel à protéger. Résolu via
   `nix::unistd::User::from_name` → uid + home dir.

6. **Persistence n'a JAMAIS de PID et ne tue donc jamais de process.**
   Contrairement à fanotify, inotify ne rapporte pas le PID de l'auteur
   d'un changement. `warden_common::response::handle_file_only_detection`
   existe spécifiquement pour ça : jamais d'appel à `stop_then_kill`.
   Piège explicitement évité : passer un PID factice comme `0` à un chemin
   qui tue des process aurait envoyé le signal à *tout le groupe de
   process appelant* (sémantique POSIX de `kill(0, sig)`) — potentiellement
   Warden lui-même. Le champ `pid` de `DetectionEvent` est un `Option<i32>`
   précisément pour ça (pas de sentinelle `0`/`-1` ambiguë dans les types
   partagés ; `-1` n'apparaît que comme valeur opaque dans le nom de
   fichier de quarantaine, jamais passé à un signal).

7. **Persistence distingue `Dotfile` (report-only, toujours) de `UnitDir`
   (quarantinable si nouveau fichier, en mode Enforce).** Éditer
   `~/.bashrc`/`authorized_keys`/`/etc/sudoers` en place n'est jamais
   automatiquement annulé (risque de casser une vraie modification
   utilisateur, et pour sudoers : un revert raté peut verrouiller tous les
   admins hors de sudo). Un *nouveau* fichier apparaissant dans un
   `UnitDir` (cron.d, sudoers.d, autostart, unités systemd) est en
   revanche sûr à mettre en quarantaine tel quel : rien de légitime n'y
   stocke de vrai travail, le fichier EST le mécanisme de persistance ou
   il ne l'est pas.

8. **Capacités systemd : `CAP_SYS_ADMIN`, `CAP_KILL`, `CAP_DAC_OVERRIDE`.**
   Le troisième a été ajouté après un vrai bug trouvé en testant en
   conteneur : `$HOME` est en `0700` par défaut (`useradd -m`), et sans
   `CAP_DAC_OVERRIDE`, même root reçoit `EACCES`. Ne pas retirer cette
   capability sans re-tester contre un `$HOME` en 0700.

## Bugs réels trouvés et corrigés en testant (pas juste écrits puis oubliés)

- **`CAP_DAC_OVERRIDE` manquante** → root ne pouvait pas lire un `$HOME` en
  0700 (mode par défaut de `useradd -m` sur toute distro). Trouvé en
  testant dans un conteneur Debian réel, pas en relisant le code.
- **Duplication de détections persistence** : une seule opération d'écriture
  (`printf ... > f`) déclenche plusieurs events inotify (IN_CREATE puis
  IN_MODIFY/IN_CLOSE_WRITE) souvent regroupés dans le même batch
  `read_events()`. Traiter chaque event indépendamment produisait deux
  détections différentes (contenu partiel puis complet) pour un seul
  changement ressenti par l'utilisateur. Corrigé par dédoublonnage par
  chemin au sein d'un même batch (`seen_this_batch`), en relisant toujours
  le contenu final sur disque au moment du traitement.
- **Faux-négatif de sécurité en mode Enforce (le plus sérieux)** : le tout
  premier event pour un nouveau fichier (IN_CREATE, fichier encore vide à
  0 octet car le contenu n'a pas encore été flush par l'écrivain) était
  traité, produisait un diff vide, et **committait quand même une entrée
  baseline vide** avant de passer au event suivant. Ça marquait
  silencieusement le chemin comme "déjà connu", donc l'event suivant
  (contenu réel complet) était traité comme une *édition* d'un fichier
  préexistant plutôt que sa vraie première apparition — pour un `UnitDir`,
  ça faisait sauter la quarantaine automatique en Enforce. Reproduit de
  façon fiable (fichier autostart malveillant jamais mis en quarantaine),
  corrigé en ne committant la baseline pour un chemin encore inconnu que
  si le contenu lu est non-vide. Revalidé par test après le fix : le même
  scénario met désormais correctement le fichier en quarantaine.

## Ce qui est fait et validé par test (pas juste écrit)

Testé dans `docker/Dockerfile.test.debian` (conteneur Debian, utilisateur
`tester` avec `$HOME` en 0700, binaire lancé directement avec
`--cap-add SYS_ADMIN --cap-add KILL --cap-add DAC_OVERRIDE --cap-drop ALL`) :

**Ransomware :**
- Mode Monitor : rafale de 5 fichiers haute-entropie par un seul process
  (Perl, un seul PID — un test avec `head` en boucle bash avait d'abord
  donné un faux négatif car chaque `head` est un PID différent, confirmant
  que le tracking per-PID marche comme prévu) → détection, event au
  dispatcher, notif desktop échoue proprement (pas de session graphique).
- Mode Enforce : process attaquant simulé tué après exactement 5 fichiers
  sur 20 prévus (exit code 137), 5 fichiers quarantainés + manifest JSONL.
- Re-testé après l'ajout du module persistence (non-régression) : toujours
  OK.

**Persistence :**
- `.bashrc` : injection de ligne `curl | bash` → détectée High, jamais
  quarantainée (Dotfile), même en Enforce.
- `authorized_keys` : ajout de clé SSH inconnue → détectée High,
  report-only.
- `/etc/ld.so.preload` : apparition → détectée High, report-only.
- `/etc/cron.d/*` nouveau fichier (y compris rafale de 5 fichiers
  simultanés) → détecté, quarantainé en Enforce.
- `~/.config/autostart/*.desktop` nouveau, `Exec=` pointant vers `/tmp/` →
  détecté High (motif "chemin d'exécution suspect"), quarantainé en
  Enforce.
- `~/.config/systemd/user/*.service` nouveau avec `ExecStart=curl|bash` →
  détecté High, quarantainé en Enforce.
- `/etc/sudoers.d/*` nouveau fichier → détecté Critical, quarantainé en
  Enforce (seulement si le dossier existe déjà au démarrage - voir gaps).
- Édition anodine (`alias gs="git status"`) → détectée Medium générique,
  pas de faux "High".

`cargo test` (10 tests unitaires : 3 entropy + 4 heuristics persistence + 3
diff persistence) : OK. `cargo clippy --all-targets` sur tout le workspace :
propre, 0 warning après corrections.

## Ce qui n'est PAS fait

- **eBPF (exec/network/ptrace/privesc) via `aya`** : toolchain pas encore
  installé. Le blocage constaté était côté HÔTE (pas de rustup) — ça ne
  bloque PAS dans un conteneur Docker dédié. Prochaine étape en cours ou à
  reprendre : `docker/Dockerfile.build-ebpf` avec rustup + nightly +
  `bpf-linker` (`cargo install bpf-linker`) + `aya-tool`, puis une probe
  minimale (tracepoint `sched_process_exec`) pour valider le pipeline
  avant de construire un vrai module réseau/exec/privesc dessus.
- Module privesc dédié (au-delà de sudoers/sudoers.d déjà couverts par
  persistence) — SUID/SGID bit changes, capabilities via `setcap`,
  transitions uid inattendues — pas commencé, dépend probablement d'eBPF
  pour une vraie couverture (fanotify `FAN_ATTRIB` pourrait couvrir les
  changements de permissions sans eBPF, à évaluer).
- Module réseau — pas commencé. Piste sans eBPF : sockets netlink
  `NETLINK_INET_DIAG` en polling ; piste eBPF : meilleure visibilité
  temps réel + attribution process.
- YARA / Sigma / signatures binaires — pas commencé (explicitement
  "si trop difficile, on skip" selon l'utilisateur, mais à tenter).
- Détection fileless (navigateur, documents piégés) — pas commencé,
  dépend d'une visibilité exec (eBPF ou audit netlink).
- Gap connu et documenté (pas un bug) : un dossier persistence qui
  n'existe pas au démarrage (`/etc/cron.d`, `/etc/sudoers.d`, etc. sur un
  système qui ne les a pas encore) n'est surveillé qu'après un redémarrage
  du service, pas rétroactivement. Confirmé par test explicite. Contrairement
  au module ransomware, ce module ne crée jamais de dossier manquant
  lui-même (créer `/etc/sudoers.d` serait too invasif pour un EDR).
- `install.sh` — **volontairement repoussé en tout dernier**, après GUI,
  sur directive explicite de l'utilisateur ("faire en sorte que tous les
  agents et le core soient parfaits, puis la GUI, puis le script"). Un
  premier brouillon existe déjà (`/home/user/warden/install.sh`, inspiré de
  celui de RansomShield) mais n'est pas la priorité tant que les modules
  de détection ne sont pas exhaustifs.
- Dockerfiles de test pour les 6 autres distros de la matrice (Ubuntu,
  Fedora, RockyLinux, AlmaLinux, Arch, openSUSE Tumbleweed) — seul Debian
  existe, et en version simplifiée (binaire lancé direct, pas de systemd
  PID1 complet comme RansomShield le fait). Vrai test systemd multi-distro
  à faire une fois `install.sh` repris.
- Test de la notif desktop avec une vraie session graphique/DE simulée —
  seul le cas "pas de session" (échec propre) a été testé.
- SAST (cargo-audit / cargo-deny pour les dépendances) — pas fait.
- GUI de contrôle — explicitement après les agents/core.
- Intégration GitHub (repo distant, CI) — pas abordé.

## Images et volumes Docker déjà créés sur cette machine

- `warden-build:rockylinux` — conteneur de build (rustc 1.97.1 stable,
  clippy installé dans le volume `warden-rustup-home`)
- `warden-test:debian` — smoke test (reconstruire après tout changement de
  code : `docker build -t warden-test:debian -f docker/Dockerfile.test.debian .`)
- volumes : `warden-cargo-registry`, `warden-cargo-home`,
  `warden-rustup-home` — toujours monter les 3 ensemble
- Images de distro déjà disponibles pour construire les futurs Dockerfiles
  de test : debian, ubuntu, fedora, rockylinux, almalinux, archlinux,
  opensuse/tumbleweed sont toutes déjà pull. Alpine dispo mais hors
  périmètre officiel (musl + OpenRC, pas systemd).

## Prochaine session : par où reprendre

1. Toolchain eBPF dans un conteneur dédié (`Dockerfile.build-ebpf`), probe
   minimale exec via `aya`, puis un vrai module exec/fileless.
2. Module réseau (netlink en attendant eBPF, ou directement en eBPF si le
   toolchain est prêt).
3. Évaluer YARA (crate `yara-x` ou bindings officiels) et une détection
   Sigma simplifiée.
4. SAST : `cargo audit`/`cargo deny` intégré au build.
5. GUI de contrôle (après le point ci-dessus).
6. `install.sh` finalisé + Dockerfiles de test systemd pour les 7 distros.
