# Warden — état d'avancement

Warden est un EDR autonome pour workstations Linux, écrit en Rust. Ce
fichier existe pour reprendre le projet proprement après une coupure de
session — le lire en entier avant de continuer.

## Règle absolue de workflow

**Rien ne compile ni ne s'exécute jamais sur l'hôte.** Le code est écrit et
édité ici, dans `/home/user/warden`, mais :
- **build** → uniquement dans le conteneur `warden-build:rockylinux`
  (voir `docker/Dockerfile.build`)
- **run/test** → uniquement dans les conteneurs de test par distro
  (`docker/Dockerfile.test.*`)

Commande de build de référence :
```
docker run --rm -v /home/user/warden:/build \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -w /build warden-build:rockylinux cargo build --release
```
Deux volumes Docker persistants existent déjà pour éviter de retélécharger
les crates à chaque run : `warden-cargo-registry` (registry cargo) et
`warden-cargo-home` (créé mais pas encore monté systématiquement — à
utiliser aussi pour persister rustup/clippy entre les runs si besoin).

## Architecture générale

Workspace Cargo à 3 crates :
- `warden-common` — types partagés (`DetectionEvent`, `Severity`, `Mode`),
  et les briques réutilisables par tout futur module de détection :
  `process::stop_then_kill`, `quarantine::Quarantine`,
  `response::handle_detection`, `notify::Notifier`.
- `warden-ransomware` — détection ransomware par fanotify, porté et adapté
  de RansomShield (`/home/user/ransomshield`, projet séparé, jamais modifié
  par Warden).
- `warden-core` — binaire `warden` : config TOML, résolution de
  l'utilisateur cible, orchestrateur, dispatcher d'events.

### Décisions d'architecture importantes (et pourquoi)

1. **Réponse synchrone dans le module détecteur, jamais via le channel
   async.** `warden_common::response::handle_detection` fait
   SIGSTOP→quarantine→SIGKILL directement dans le thread bloquant du
   module fanotify, puis construit un `DetectionEvent` envoyé au
   dispatcher *seulement* pour log/notif/historique futur. Un design
   initial où le module "proposait" une action et attendait que le
   dispatcher l'exécute via un channel async a été rejeté : ça ajoute une
   latence inacceptable face à un ransomware qui chiffre activement.

2. **fanotify marque tout le mount, filtré en userspace.** Contrairement à
   RansomShield (serveur, mount dédié), `$HOME` d'une workstation est
   presque toujours sur la partition racine. `FAN_MARK_FILESYSTEM` sur un
   sous-dossier de `/` watche donc tout `/`. Solution : on accepte ce scope
   large côté kernel, mais on filtre en userspace
   (`fanotify_monitor::is_under_watch_dirs`) pour ne traiter que les events
   sous les dossiers réellement configurés. Les `watch_dirs` sont
   canonicalisés (résout aussi le cas où l'un d'eux est un symlink) et le
   `~` est expansé manuellement (TOML n'est pas un shell, serde ne le fait
   pas).

3. **Notification desktop via zbus, connexion explicite au bus de session
   de l'utilisateur cible** (`unix:path=/run/user/<uid>/bus`), pas de
   découverte auto via `DBUS_SESSION_BUS_ADDRESS`. Warden tourne en root ;
   un service systemd root n'a pas de session de bus utilisateur, donc la
   découverte auto pointerait vers rien. Root peut ouvrir ce socket malgré
   ses permissions 0700 (bypass DAC). Testé : échoue proprement (log warn,
   pas de crash) dans un conteneur headless sans session graphique — c'est
   le comportement attendu, à revalider avec une vraie session DE plus
   tard.

4. **`target_user` explicite en config, pas d'auto-détection.** Root n'a
   pas de `$HOME` personnel à protéger. Résolu via
   `nix::unistd::User::from_name` → uid + home dir.

5. **Capacités systemd : `CAP_SYS_ADMIN`, `CAP_KILL`, et `CAP_DAC_OVERRIDE`.**
   Le troisième a été ajouté après un vrai bug trouvé en testant en
   conteneur : `$HOME` est en `0700` par défaut (`useradd -m`), et sans
   `CAP_DAC_OVERRIDE`, même root en reçoit `EACCES`. Ne pas retirer cette
   capability sans re-tester contre un `$HOME` en 0700.

## Ce qui est fait et validé par test (pas juste écrit)

Testé dans `docker/Dockerfile.test.debian` (conteneur Debian, utilisateur
`tester` avec `$HOME` en 0700, binaire lancé directement avec
`--cap-add SYS_ADMIN --cap-add KILL --cap-add DAC_OVERRIDE --cap-drop ALL`) :

- Démarrage, résolution de `target_user`, marquage fanotify avec
  dédoublonnage par device, scan de baseline, provisioning des honeypots.
- **Mode Monitor** : rafale de 5 fichiers haute-entropie écrits par un
  seul process (simulateur Perl, un seul PID — un test avec `head` en
  boucle bash a d'abord donné un faux négatif car chaque `head` est un PID
  différent, ce qui a confirmé que le tracking per-PID fonctionne comme
  prévu, pas un bug) → détection déclenchée, event envoyé au dispatcher,
  notif desktop tentée et échoue proprement (pas de session graphique dans
  le conteneur), daemon continue de tourner normalement après.
- **Mode Enforce** : process attaquant simulé (boucle de 20 écritures)
  effectivement tué après exactement 5 fichiers (exit code 137), 5
  fichiers mis en quarantaine avec manifest JSONL, 14 fichiers restants
  jamais écrits.
- `cargo test` (3 tests unitaires sur `shannon_entropy`) : OK.
- `cargo clippy --all-targets` : 2 warnings de style corrigés
  (`needless_borrows_for_generic_args` sur `lseek`/`read`), rien d'autre.

## Ce qui n'est PAS fait

- **eBPF (exec/network/ptrace/privesc) via `aya`** : bloqué sur l'hôte par
  l'absence de rustup/nightly/bpf-linker, mais rien n'empêche de les
  installer *dans un conteneur Docker dédié* (le blocage était une
  limitation de l'hôte, pas une contrainte réelle) — prochaine étape
  logique : construire `Dockerfile.build-ebpf` avec rustup + toolchain
  nightly + `bpf-linker` (`cargo install bpf-linker`) + `aya-tool`.
- Module persistence (cron, systemd units, bashrc/profile, autostart
  XDG, etc.) — pas commencé.
- Module privesc — pas commencé.
- Module réseau — pas commencé.
- YARA / Sigma / signatures binaires — pas commencé (explicitement
  "si trop difficile, on skip" selon l'utilisateur).
- Détection fileless (navigateur, documents piégés) — pas commencé.
- `install.sh` — pas écrit. RansomShield en a un bon (`/home/user/ransomshield/install.sh`,
  lu et pris comme référence : preflight checks, build, ne jamais écraser
  une config existante, unit systemd + drop-in `ReadWritePaths` généré
  dynamiquement, vérification via `journalctl` avant de déclarer le
  succès). Celui de Warden devra en plus déterminer/demander le
  `target_user` (RansomShield n'a pas cette notion).
- Dockerfiles de test pour les 6 autres distros de la matrice
  (Ubuntu, Fedora, RockyLinux, AlmaLinux, Arch, openSUSE Tumbleweed) —
  seul Debian existe (`docker/Dockerfile.test.debian`), et c'est une
  version simplifiée (binaire lancé direct, pas de systemd PID1 complet
  comme RansomShield le fait). Il faudra un vrai smoke test par systemd
  (comme `ransomshield`'s `Dockerfile.debian` avec `/sbin/init`, cgroups
  montés, etc.) pour valider l'installation via `install.sh` sur chaque
  distro, pas juste le binaire nu.
- Test de la notif desktop avec une vraie session graphique/DE simulée
  (dunst/mako/GNOME Shell tournant dans un conteneur) — seul le cas
  "pas de session" a été testé.
- SAST (cargo-audit / cargo-deny pour les dépendances, a minima).
- GUI de contrôle — explicitement "à faire en dernier" selon l'utilisateur.
- Intégration GitHub (repo distant, CI) — pas encore abordé.

## Images et volumes Docker déjà créés sur cette machine

- `warden-build:rockylinux` — conteneur de build (rustc 1.97.1 stable)
- `warden-test:debian` — smoke test (à reconstruire après tout changement
  de code : `docker build -t warden-test:debian -f docker/Dockerfile.test.debian .`)
- volumes `warden-cargo-registry`, `warden-cargo-home`
- Images de distro déjà disponibles pour construire les futurs
  Dockerfiles de test : voir `docker images` — debian, ubuntu, fedora,
  rockylinux, almalinux, archlinux, opensuse/tumbleweed sont toutes déjà
  pull. Alpine disponible mais explicitement hors périmètre officiel
  (musl + OpenRC, pas systemd).

## Prochaine session : par où reprendre

1. Écrire `install.sh` (inspiré de celui de RansomShield) + tester son
   déploiement complet dans `Dockerfile.test.debian` version systemd-PID1.
2. Dupliquer `Dockerfile.test.debian` pour les 6 autres distros de la
   matrice.
3. Décider et démarrer soit le module persistence, soit le toolchain eBPF
   (les deux sont indépendants et peuvent être faits dans n'importe quel
   ordre).
