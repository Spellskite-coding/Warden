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

## Toolchain eBPF — validé de bout en bout (docker/Dockerfile.build-ebpf)

Le blocage initial était côté HÔTE uniquement (pas de rustup) ; aucun
blocage réel dans un conteneur Docker dédié. Toolchain fonctionnel construit
et **validé par un chargement réel dans le kernel**, pas juste compilé :

- Base Debian bookworm, LLVM 23 installé via `apt.llvm.org` (script `llvm.sh
  23`), rustup avec toolchain stable (pour `bpf-linker`) + nightly +
  `rust-src` (pour compiler la cible `bpfel-unknown-none` via `-Z
  build-std=core`), `cargo install bpf-linker --no-default-features
  --features llvm-23`.
- **Piège découvert par test, pas évident à l'avance** : `bpf-linker` doit
  être lié contre la MÊME version majeure de LLVM que celle embarquée dans
  le rustc nightly actif (`rustup run nightly rustc --version --verbose` →
  `LLVM version: 23.1.0`), sinon erreur cryptique `ERROR llvm: Invalid
  record` au link. Comme les toolchains nightly changent de version LLVM
  interne au fil du temps, **revérifier cette correspondance avant de
  réutiliser cette image après une longue pause** (voir section
  "Maintenance" plus bas).
- **Piège Docker découvert par test** : ne jamais monter les volumes
  `warden-cargo-home`/`warden-rustup-home` (ceux du conteneur RockyLinux
  stable) sur le conteneur `warden-build:ebpf` — ça masque le nightly +
  bpf-linker installés dans l'image avec un volume vide d'un autre
  toolchain. Pour ce conteneur, monter uniquement `warden-cargo-registry`
  (cache de paquets, sans rapport avec le toolchain, sans risque).
- Crates : `aya` 0.14.0 / `aya-ebpf` 0.2.1 / `aya-build` 0.2.0 (gère la
  compilation croisée de la crate eBPF via `build.rs`, voir
  `ebpf-probe/warden-exec/build.rs`).
- **`aya-log`/`aya-log-ebpf` (0.3.0/0.2.0) cassent le chargement** :
  `BPF_PROG_LOAD` échoue avec `fd 10 is not pointing to valid bpf_map`
  (vérifié par test, pas juste supposé). Contournement adopté pour la
  probe de validation : pas de `aya-log`, une simple map `Array<u64>`
  incrémentée côté kernel et lue en polling côté userspace. Marche
  parfaitement. À creuser avant d'utiliser `aya-log` dans un vrai module
  (bug de version, ou map créée dans le mauvais ordre - pas encore
  diagnostiqué).
## Module exec (`ebpf-probe/`) — implémenté et validé end-to-end

`ebpf-probe/` reste un **workspace séparé** de celui principal de warden
(voir "Pourquoi `ebpf-probe/` reste un workspace séparé" plus bas pour la
raison structurelle - ce n'est pas un oubli). Deux crates :

- `warden-exec-ebpf` (programme kernel) : tracepoint
  `sched:sched_process_exec`, parse le champ `__data_loc filename` du
  format tracepoint (vérifié via `/sys/kernel/tracing/events/sched/
  sched_process_exec/format` - offset 8 = `__data_loc` du filename, offset
  12 = pid) via `bpf_probe_read_kernel_str_bytes` (pas la variante
  `bpf_probe_read_kernel_str`, dépréciée), pousse `{pid, filename}` dans
  une `RingBuf`.
- `warden-exec` (loader userspace) : charge/attache la probe, lit la
  `RingBuf` en async via `tokio::io::unix::AsyncFd`, résout `target_user`
  (config TOML partagée avec le `warden` principal - seuls `mode` et
  `target_user` sont lus, le reste ignoré par serde), flague toute
  exécution depuis un chemin suspect (`warden_common::heuristics`,
  factorisé et réutilisé aussi par le module persistence) ou depuis
  `~/Downloads` du `target_user`, puis appelle
  `warden_common::response::handle_detection` (kill + quarantine du
  binaire exécuté) - **contrairement à persistence, ce module A un PID
  fiable** (fourni par le tracepoint), donc peut légitimement tuer le
  process, pas juste observer.

**Testé en conditions réelles**, pas juste compilé :
- `cargo test -p warden-exec` : 6/6 (parsing d'event, détection de
  chemin suspect).
- `cargo clippy` propre sur les deux crates (le crate kernel avec son
  toolchain/target propres : `rustup run nightly cargo clippy --target
  bpfel-unknown-none -Z build-std=core`, sinon clippy tente de le
  compiler pour l'hôte et échoue - "unwinding panics are not supported
  without std", pas un vrai bug).
- Chargé dans un vrai conteneur privilégié avec `/sys/kernel/debug` et
  `/sys/kernel/tracing` montés : exécution d'un faux malware depuis
  `/tmp` → tué + binaire quarantiné en quelques millisecondes ; exécutions
  normales (`whoami`, `ls`, `cat`) jamais touchées.
- **Piège de test découvert et documenté** : sans `--pid=host` sur le
  conteneur de test, le kill échoue avec `ESRCH` - eBPF rapporte le PID
  *global de l'hôte* (le kernel n'est pas namespace-aware pour les
  tracepoints), alors que le process warden-exec tournant dans un
  conteneur voit son PROPRE PID namespace. Sur un vrai déploiement
  (systemd sur la machine hôte, sans conteneur), ce problème n'existe pas
  puisqu'il n'y a qu'un seul PID namespace - mais tout test futur de ce
  module doit utiliser `--pid=host` pour être représentatif.

**Capacités utilisées pour le test** : `--privileged` (large, pour aller
vite). Pas encore réduit à l'ensemble minimal réel (`CAP_BPF` +
`CAP_PERFMON` + `CAP_KILL` + accès tracefs probablement suffisant sur
kernel 5.8+) - à déterminer avant d'écrire l'unit systemd de ce module.

**`aya-log` toujours cassé** (voir plus haut, `fd 10 is not pointing to
valid bpf_map`) - non utilisé, pas nécessaire pour ce module qui pousse
des données structurées via sa propre `RingBuf`, pas des logs texte.

### Pourquoi `ebpf-probe/` reste un workspace séparé (pas un oubli)

`warden-exec-ebpf` est `#![no_std]` et ne peut être compilé QUE pour la
cible `bpfel-unknown-none` via nightly + `-Z build-std=core` - le
compiler pour la cible hôte (ce qu'un `cargo build --release` nu à la
racine d'un workspace ferait pour TOUS ses membres) échoue purement et
simplement. Si `warden-exec-ebpf`/`warden-exec` rejoignaient le workspace
principal (celui de `warden-build:rockylinux`, toolchain stable
uniquement, pas de nightly/bpf-linker), la commande de build habituelle
`cargo build --release` casserait. `warden-exec` dépend bien de
`warden-common` par chemin relatif (`../../warden-common`) et se compile
très bien avec le toolchain stable de `warden-build:ebpf` (Debian
bookworm a aussi un rustc stable normal) - seul le crate kernel a besoin
du nightly, via le `build.rs` de `warden-exec` (`aya-build`) qui shell-out
vers `rustup run nightly cargo build --target bpfel-unknown-none`,
une invocation cargo totalement séparée qui ne pollue jamais la
résolution du workspace principal.

**Prochaine étape** : soit garder `warden-exec` comme binaire/service
systemd autonome (notifie via son propre `Notifier`, pas de bus
d'événements partagé avec `warden-core` pour l'instant - duplication
mineure et acceptée pour l'instant), soit construire un bus d'événements
local (socket Unix, JSON ligne par ligne) une fois que 2-3 modules eBPF
de plus existent et que la duplication commence à peser - pas fait
maintenant, noté comme refacto propre à venir.

## Maintenance et mises à jour (question posée par l'utilisateur, à traiter sérieusement)

Warden aura besoin d'un vrai cycle de maintenance, pas d'un build unique :
- **Dépendances Rust** : `Cargo.lock` est committé exprès pour des builds
  reproductibles ; toute mise à jour doit être délibérée (bump +
  re-test complet sur la matrice de conteneurs), jamais un `cargo update`
  aveugle sur un outil qui tourne en root. `aya` est encore pré-1.0 (0.14.x)
  et casse son API entre versions mineures - étudier le changelog avant de
  bumper.
- **Pin LLVM/nightly pour le toolchain eBPF** : le plus fragile des deux
  toolchains. Avant de reconstruire `warden-build:ebpf` après une longue
  pause, revérifier `rustup run nightly rustc --version --verbose` contre
  la version LLVM installée dans le Dockerfile - un nightly plus récent
  peut embarquer une version LLVM différente et recasser `bpf-linker`.
- **Tâche restant à faire** (demandée explicitement par l'utilisateur) :
  un mécanisme simple pour vérifier rapidement "y a-t-il une mise à jour à
  appliquer" et l'appliquer vite. Idée pas encore implémentée : un script
  `scripts/check-updates.sh` qui lance `cargo outdated`/`cargo audit` sur
  le workspace principal ET sur `ebpf-probe/`, et vérifie la correspondance
  LLVM/nightly ci-dessus automatiquement (compare la version LLVM du
  nightly actif à celle indiquée dans `Dockerfile.build-ebpf`). Pas encore
  écrit - à faire.
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
