# Warden — état d'avancement

Warden est un EDR autonome pour workstations Linux, écrit en Rust. Ce
fichier existe pour reprendre le projet proprement après une coupure de
session — le lire en entier avant de continuer.

L'utilisateur a donné le feu vert pour travailler en autonomie complète
(core, agents, DAST, SAST, GUI, tests réels en conteneurs, YARA/Sigma,
tout) sans notifier chaque avancée dans le chat — un point d'étape complet
suffit. Priorité explicite : **finir tous les agents de détection + le core
d'abord, GUI ensuite, `install.sh` en tout dernier.**

## Module réseau + SAST — faits et validés (reprise après pause)

**Module réseau** (`ebpf-probe/warden-network-ebpf` + `warden-network`,
même structure que le module exec) : hook sur le tracepoint
`sock:inet_sock_set_state`, ne traite que la transition vers
`TCP_SYN_SENT` (pas `TCP_ESTABLISHED` - cette dernière est souvent
atteinte de façon asynchrone dans un contexte softirq quand le SYN-ACK
arrive, où le pid "courant" n'est plus celui qui a initié la connexion).
Résout `/proc/<pid>/exe` côté userspace et applique la même heuristique de
localisation suspecte que le module exec (`warden_common::heuristics::is_suspicious_exec_location`,
maintenant partagée par les deux modules) - défense en profondeur : si un
process depuis `/tmp` ouvre une connexion sortante, tué + binaire
quarantiné, même si le module exec ne l'avait pas déjà attrapé au
lancement.

**Bug réel trouvé et corrigé par test** : le champ `common_pid` du
tracepoint (offset 4, documenté dans son propre format) donnait une valeur
absurde (négative, et IDENTIQUE pour deux process pourtant différents) une
fois lu côté eBPF - alors que `dport`/`daddr` lus depuis le même tracepoint
étaient corrects, écartant un bug d'offset généralisé. Remplacé par
`bpf_get_current_pid_tgid() >> 32`, lu depuis la tâche en cours plutôt que
depuis l'enregistrement de trace - l'approche standard qu'utilisent aussi
bcc/bpftrace pour ce tracepoint précis. Revalidé par test : pid correct
pour deux connexions simultanées distinctes.

**Bug structurel réel trouvé et corrigé dans `ebpf-probe/Cargo.toml`** :
un `cargo build`/`test`/`clippy` NU (sans `-p`) à la racine du workspace
tentait de compiler les crates `*-ebpf` (`#![no_std]`/`#![no_main]`) pour
la cible hôte par défaut - échec direct ("unwinding panics are not
supported without std" en build, "undefined symbol: main" en test), plus
une collision de nom de binaire de sortie entre `warden-exec` (userspace)
et le bin du crate `warden-exec-ebpf` qui porte le même nom. L'hypothèse
initiale ("un build nu ne les touche jamais, seul le build.rs les
compile") était fausse et corrigée en le testant réellement. Fix :
`default-members = ["warden-exec", "warden-network"]` dans
`ebpf-probe/Cargo.toml` - les crates `*-ebpf` restent des `members`
(donc toujours accessibles via `-p` explicite ou via le `build.rs`), mais
un `cargo build`/`test`/`clippy` sans arguments ne cible plus qu'elles.

**Testé en conditions réelles** (conteneur `--privileged --pid=host`,
tracefs monté, listener `nc -l` local) : connexion depuis `/usr/bin/nc`
(légitime) jamais flaguée ; le même binaire copié vers `/tmp` et utilisé
pour se connecter → détecté, tué, quarantiné en Enforce. `cargo test`
(9 tests sur tout `ebpf-probe/` : 6 exec + 3 network) et `cargo clippy`
propres sur les 4 crates (2 userspace + 2 kernel, ces derniers avec leur
target/toolchain propres).

**SAST intégré** : `cargo-audit` installé (persisté dans le volume
`warden-cargo-home`), `scripts/check-updates.sh` écrit et testé de bout
en bout - vérifie la correspondance LLVM/nightly (voir plus haut) ET lance
`cargo audit` sur les deux workspaces (le principal ET `ebpf-probe/`).
Résultat actuel : **0 vulnérabilité connue**, toolchain eBPF toujours
aligné (LLVM 23/LLVM 23). À relancer périodiquement, surtout après tout
`cargo update` ou changement de toolchain.

## Module privesc — fait, mais PAS en fanotify (limitation kernel réelle, pas un choix)

Nouveau crate `warden-privesc` (dans le workspace principal, pas
`ebpf-probe/` - pas besoin d'eBPF pour celui-ci). Détecte l'apparition
d'un bit setuid/setgid : sur un binaire système déjà connu (technique
GTFOBins, ex. `chmod +s /usr/bin/find`) → le bit est retiré (Enforce),
le binaire n'est jamais supprimé ; sur un fichier tout nouveau dans
`/tmp`, `/var/tmp`, `/dev/shm` ou `$HOME` (ex. copie de bash + `chmod +s`)
→ mis en quarantaine comme les autres modules "nouveau fichier".

**Tentative fanotify abandonnée après un vrai test, pas une supposition** :
`FAN_ATTRIB` échoue systématiquement avec `EINVAL`, quel que soit le scope
du mark (filesystem-wide OU un simple dossier non-récursif) - confirmé en
isolant le test (`FAN_MODIFY` marche en contrôle, `FAN_ATTRIB` échoue
systématiquement, y compris combiné à `FAN_EVENT_ON_CHILD`/`FAN_ONDIR`).
Raison : `FAN_ATTRIB` fait partie des "directory entry events" du kernel
qui nécessitent que le groupe fanotify soit initialisé avec
`FAN_REPORT_FID` - un flag que les bindings `nix` 0.31.3 n'exposent PAS
dans `InitFlags` (vérifié dans le source de la crate). Contourner ça
demanderait soit des appels syscall bruts (et `nix` ne sait de toute façon
pas parser le format d'event FID différent que ça produirait), soit un
hook eBPF sur la famille de syscalls `chmod`. Les deux sont plus lourds
que ce qu'une surface privesc (pas aussi time-critique qu'un ransomware
actif ou un exec/connexion en direct) justifie pour une première version.

**Solution retenue : polling toutes les 5 secondes.** Plus simple, correct,
sans acrobaties sur les syscalls. Modèle d'état à deux ensembles :
`baseline` (immuable, établi une fois au démarrage - tout ce qui est déjà
setuid/setgid à ce moment-là est présumé légitime pour toujours) et
`already_flagged` (mutable, évite de re-notifier à chaque tick de 5s pour
une même anomalie non résolue, réinitialisé dès que le fichier disparaît
du scan - une vraie ré-infection après remédiation redevient un incident
neuf).

**Bug réel trouvé et corrigé en testant** : `/bin` et `/sbin` sont des
symlinks vers `/usr/bin`/`/usr/sbin` sur toute distro usr-merge (la
plupart des distros modernes). Sans déduplication, le même fichier
physique était scanné deux fois sous deux chemins différents,
produisant deux détections pour un seul `chmod +s` (`/usr/bin/find` ET
`/bin/find` flagués séparément, vu en pratique). Corrigé en canonicalisant
et dédupliquant les dossiers de watch avant le scan (`known_suid_sgid`
est passé de 22 à 11 après le fix - preuve que le doublon existait bel et
bien, pas juste une hypothèse).

**Testé en conditions réelles** (conteneur `--privileged`, `mode=enforce`) :
- Binaire déjà setuid au démarrage (`/usr/bin/passwd`) re-touché →
  jamais flagué (baseline).
- Binaire système gagnant le bit pour la première fois
  (`chmod +s /usr/bin/find`, technique GTFOBins) → détecté Critical, bit
  retiré, binaire toujours présent et fonctionnel.
- Nouveau fichier setuid dans `/tmp` (bash copié + `chmod +s`) → détecté
  Critical, **mis en quarantaine** (jamais de kill pour ce module : le
  polling ne fournit aucun PID, contrairement à fanotify), fichier
  effectivement retiré de `/tmp`.

**`warden-core/src/main.rs` refactorisé** : avec un 3ème module, dupliquer
le pattern manuel "spawn + oneshot ready + branche `select!`" par module
devenait source d'erreurs (exactement le genre de bug que je viens de
corriger dans la logique privesc elle-même). Remplacé par un superviseur
générique basé sur `tokio::task::JoinSet<(&'static str, Result<()>)>` +
une fonction `spawn_module` réutilisable - le nom du module transite dans
la valeur de retour de la tâche elle-même, donc `JoinSet::join_next`
identifie directement quel module vient de se terminer sans table de
correspondance séparée à tenir à jour.

## Module YARA — fait et validé

Nouveau crate `warden-yara` (workspace principal), même pattern fanotify
que ransomware (`FAN_CLOSE_WRITE`, mount-dedup, filtrage userspace) mais
scanne le fichier fermé avec `yara-x` (réimplémentation pure Rust de YARA,
compile les conditions de règles en WASM exécuté via `wasmtime` en interne
- pas quelque chose qu'on pilote directement) au lieu de calculer
l'entropie. Watch dirs par défaut : `Downloads`, `Desktop`, `Documents`
sous `$HOME`, + `/tmp`. Jamais de kill (contrairement à ransomware) : le
process qui a fermé le fichier (navigateur, `curl`, gestionnaire de
téléchargement) n'a fait qu'écrire le contenu, il ne l'exécute pas -
`response::handle_file_only_detection` (quarantine seule) suffit et évite
de tuer un programme par ailleurs parfaitement légitime.

**Règles intégrées** (`warden-yara/rules/builtin.yar`, testées
individuellement contre des échantillons réalistes avant intégration, pas
juste écrites à l'aveugle) : fichier de test EICAR (le standard de
l'industrie AV, inoffensif par design), reverse shell bash
(`/dev/tcp`+`exec`), reverse shell netcat (`-e`), reverse shell Python
(`socket`+`dup2`+`pty.spawn`), webshell PHP obfusqué
(`eval`/`system`+`base64_decode`+`$_POST`), pipe base64→shell. Extensible
via `/etc/warden/yara-rules/*.yar` (custom_rules_dir configurable),
compilés en plus du set intégré au démarrage.

**Dépendances allégées, un vrai souci trouvé et corrigé** : les features
par défaut de `yara-x` tirent les modules PE/Mach-O/.NET/DEX/CRX/LNK
(parsers de formats binaires Windows/macOS/Android) et leur crypto
associée (RSA, X.509, ECDSA, DSA) - rien de pertinent pour un EDR
workstation Linux dont les règles ne référencent que du texte/regex.
Compilé avec `default-features = false` + seulement
`constant-folding, exact-atoms, fast-regexp, generate-proto-code,
elf-module, string-module, hash-module, math-module, time-module` -
confirmé par test que ça retire bien `rsa`/`x509-parser`/`ecdsa`/`dsa`/
`zip`/`uuid`/`roxmltree` de l'arbre de dépendances sans casser la
compilation ni les règles. `wasmtime` reste : ce n'est pas un module
optionnel, c'est le moteur d'exécution central de yara-x pour TOUTE
condition de règle, impossible à retirer.

**Finding SAST réel traité, pas juste ignoré** : `cargo audit` a remonté
`RUSTSEC-2026-0222` (wasmtime "Stores can mix up type indices between
engines", CVSS 3.8 bas, `AV:L/AC:H/PR:H/UI:R` - accès local, complexité
et privilèges élevés ET interaction utilisateur requis) tiré
transitivement par `yara-x` 1.19.0 (déjà la dernière version disponible,
pas de fix à obtenir en bumpant). Le bug ne se manifeste que si
l'application mélange plusieurs instances `wasmtime::Engine` - yara-x
n'en utilise qu'une en interne, donc pas atteignable via notre usage.
Décision documentée (pas un silence) dans `.cargo/audit.toml` avec le
raisonnement complet et un rappel de réévaluer dès qu'une nouvelle
version de `yara-x` sort. Un warning "unmaintained" séparé sur `bincode`
(transitif via wasmtime aussi) reste affiché mais ne fait pas échouer le
check (politique par défaut de `cargo audit` pour les advisories de type
"warning").

**Testé en conditions réelles** (conteneur, `mode=enforce`) : fichier
EICAR déposé dans `Downloads` → détecté (`Eicar_Test_File`), quarantiné,
retiré du dossier. Script reverse-shell bash déposé → détecté
(`Bash_Dev_Tcp_Reverse_Shell`), quarantiné. Fichier texte ordinaire →
jamais touché. Confirmé aussi que plusieurs modules fanotify indépendants
(ransomware ET yara, groupes fanotify séparés) peuvent surveiller le même
mount avec des masques d'events différents sans conflit - le honeypot de
ransomware (`.warden_canary`) reste intact et non perturbé par le module
yara tournant en parallèle sur le même dossier.

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

Workspace Cargo principal à 6 crates (plus le workspace séparé
`ebpf-probe/` pour les modules exec/network, voir plus bas) :
- `warden-common` — types partagés (`DetectionEvent`, `Severity`, `Mode`),
  et les briques réutilisables par tout module de détection :
  `process::stop_then_kill`, `quarantine::Quarantine`,
  `permissions::strip_setuid_setgid`, `heuristics` (localisations
  suspectes, partagé entre plusieurs modules), `target::resolve` (résolution
  de l'utilisateur cible), `response::handle_detection` (réponse avec PID,
  kill+quarantine), `response::handle_file_only_detection` (réponse SANS
  PID, quarantine seule — voir point 6 ci-dessous), `notify::Notifier`.
- `warden-ransomware` — détection ransomware par fanotify, porté et adapté
  de RansomShield (`/home/user/ransomshield`, projet séparé, jamais modifié
  par Warden).
- `warden-persistence` — détection de persistance par inotify (bashrc,
  cron, autostart XDG, unités systemd, sudoers, authorized_keys,
  ld.so.preload). Détails complets plus bas.
- `warden-privesc` — détection SUID/SGID par polling (pas fanotify, voir
  section dédiée plus haut pour pourquoi).
- `warden-yara` — scan YARA (`yara-x`) des fichiers nouvellement écrits
  dans Downloads/Desktop/Documents/tmp, par fanotify.
- `warden-core` — binaire `warden` : config TOML, résolution de
  l'utilisateur cible, orchestrateur multi-module (`tokio::task::JoinSet`),
  dispatcher d'events.

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

4. **Notification desktop : jamais de connexion D-Bus directe depuis le
   démon root.** dbus-daemon refuse par construction qu'un uid étranger
   au bus de session complète le `Hello` (confirmé sur vraie VM, voir la
   section dédiée plus bas) - donc `Notifier` spawn un binaire séparé,
   `warden-notify-helper`, avec privilèges tombés à l'uid/gid de
   l'utilisateur cible (`Command::uid()/gid()`), qui lui seul se connecte
   au bus (`unix:path=/run/user/<uid>/bus`) et communique avec le démon
   parent en JSON sur stdin/stdout. Validé end-to-end sur VM réelle.

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
- Module privesc : **fait pour SUID/SGID** (voir plus haut, polling 5s -
  fanotify `FAN_ATTRIB` s'est révélé impossible avec les bindings `nix`
  actuels, pas juste "pas encore évalué"). Pas encore couvert :
  capabilities Linux via `setcap` (`getcap`/`setcap` sur un binaire,
  vecteur privesc équivalent au SUID mais orthogonal, même limitation
  fanotify probable), transitions uid inattendues (nécessiterait eBPF,
  voir le module exec pour le pattern à réutiliser).
- Module réseau : **fait** (voir plus haut) - couvre les connexions TCP
  sortantes (IPv4/IPv6) depuis un binaire en localisation suspecte. Pas
  encore couvert : UDP, connexions entrantes/écoute (utile pour détecter
  un binaire malveillant qui ouvre un port en backdoor), et une liste
  blanche pour les faux positifs légitimes (ex. un vrai outil de backup
  qui tournerait depuis un chemin inhabituel).
- YARA / Sigma / signatures binaires — pas commencé (explicitement
  "si trop difficile, on skip" selon l'utilisateur, mais à tenter).
- Détection fileless (navigateur, documents piégés) — **partiellement
  couvert** par les modules exec + réseau (exécution et connexions
  sortantes depuis `/tmp`, `/dev/shm`, `~/Downloads`). Ce qui manque
  encore : visibilité sur la chaîne parent→enfant (ex. navigateur qui
  spawn un shell) et sur le contenu réellement piégé d'un document avant
  exécution (couverture a priori, pas juste a posteriori).
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
- SAST : **fait pour cargo-audit** (voir plus haut,
  `scripts/check-updates.sh`). `cargo-deny` (licences + bans de crates,
  au-delà des seules CVE) pas encore ajouté - amélioration possible mais
  pas critique.
- GUI de contrôle — explicitement après les agents/core.
- Intégration GitHub (repo distant, CI) — pas abordé.

## Images et volumes Docker déjà créés sur cette machine

- `warden-build:rockylinux` — conteneur de build principal (rustc 1.97.1
  stable, clippy + **cargo-audit** installés dans le volume
  `warden-rustup-home`/`warden-cargo-home`)
- `warden-build:ebpf` — conteneur de build eBPF (Debian bookworm, nightly +
  rust-src + bpf-linker(LLVM 23) + clippy pour les deux toolchains,
  baked-in dans l'image elle-même, ne PAS monter
  `warden-cargo-home`/`warden-rustup-home` dessus - voir la section
  toolchain eBPF plus haut pour pourquoi)
- `warden-test:debian` — smoke test (reconstruire après tout changement de
  code : `docker build -t warden-test:debian -f docker/Dockerfile.test.debian .`)
- volumes : `warden-cargo-registry` (partagé, sans risque sur tous les
  conteneurs), `warden-cargo-home` + `warden-rustup-home` (réservés à
  `warden-build:rockylinux`, jamais montés sur `warden-build:ebpf`)
- Images de distro déjà disponibles pour construire les futurs Dockerfiles
  de test : debian, ubuntu, fedora, rockylinux, almalinux, archlinux,
  opensuse/tumbleweed sont toutes déjà pull. Alpine dispo mais hors
  périmètre officiel (musl + OpenRC, pas systemd).

## Historique persistant + notifications actionnables (2 des 3 prérequis GUI) — faits

**Historique** : `warden_common::history::HistoryStore` - chaque
`DetectionEvent` a désormais un `id` stable (module + timestamp
nanoseconde, pas besoin de compteur partagé entre modules qui tournent
chacun sur leur propre thread, ni de dépendance uuid/rand en plus).
Chaque event est append-only en JSONL dans `/var/lib/warden/history.jsonl`
via le dispatcher. Testé en conteneur : deux détections persistence
atterrissent bien dans le fichier avec des ids distincts.

**Notifications actionnables** : `Notifier` déclare maintenant une action
D-Bus (`"default"`, "View details") sur chaque `Notify()`, capture l'id
de notification retourné, et un thread de fond persistant écoute le
signal `ActionInvoked` sur le bus de session de l'utilisateur cible pour
faire le lien avec l'`id` de l'incident (corrélation en mémoire, purge
après 24h si jamais cliqué). Le lancement effectif de la GUI au clic est
un `TODO` explicite (`warden_common::notify::run_action_listener`) tant
que `warden-gui` n'existe pas - la corrélation elle-même est du code
fonctionnel, pas un stub.

### Investigation D-Bus : root cause réelle trouvée sur vraie VM Kali, corrigée, et round-trip validé de bout en bout

L'hypothèse "limitation de sandbox" notée précédemment ici était
**incomplète et en partie fausse** - corrigée après test sur une vraie VM
Kali fournie par l'utilisateur (pas de conteneurs imbriqués). Le même
échec de connexion `zbus` s'est reproduit à l'identique sur dbus-daemon
1.16.2 (Kali) comme sur 1.14.10 (sandbox d'origine), ce qui écartait
définitivement "artefact de sandbox" comme explication complète.

**Root cause réelle, confirmée par `strace` comparatif côte à côte** :
quand le process qui se connecte a un uid différent du propriétaire du
bus de session (ex. root, uid 0, essayant de joindre le bus de `kali`,
uid 1000), dbus-daemon accepte le `AUTH EXTERNAL` (root peut ouvrir le
socket 0700 malgré les permissions, les vérifications DAC ne s'appliquant
pas à root), négocie même `AGREE_UNIX_FD`, puis **ferme silencieusement
la connexion sans jamais traiter le `Hello` pipeliné** - confirmé
identique sur les deux versions de dbus-daemon testées. À l'inverse, une
connexion **même uid** (testé : `kali` se connectant à son propre bus)
réussit avec exactement le même pattern de négociation pipelinée. Un
troisième test avec un uid tiers non-root (`wardentest`, 1001) échoue
encore plus tôt, avec un `EACCES` au niveau du socket lui-même (les
permissions fichier 0700 bloquent tout uid non-root et non-propriétaire).
La policy XML de session (`session.conf`) est entièrement permissive
(`allow send_destination="*"`, `allow own="*"`) - ce n'est donc pas une
policy XML qui bloque, c'est un contrôle interne de dbus-daemon,
indépendant de toute configuration, qui refuse silencieusement le `Hello`
d'un uid étranger au bus. **Conclusion : ce n'est ni un bug Warden, ni un
bug zbus, ni un artefact de sandbox - c'est un durcissement volontaire de
dbus-daemon qui empêche par construction un process root de rejoindre le
bus de session d'un autre utilisateur.**

**Fix appliqué** : `Notifier` (`warden_common::notify`) ne se connecte
plus jamais lui-même à un bus D-Bus. Il spawn désormais un nouveau
binaire, `warden-notify-helper` (nouveau crate), avec ses privilèges
tombés à l'uid/gid de l'utilisateur cible via
`tokio::process::Command::uid()/gid()` - ce qui fait que la connexion se
fait bien avec le même uid que le propriétaire du bus, cas qui marche.
Le helper est entièrement non-privilégié, communique avec le démon root
parent via stdin/stdout en JSON ligne-par-ligne (requêtes de notification
dans un sens, clics `ActionInvoked` corrélés dans l'autre), et reprend
telle quelle la logique de reconnexion/écoute qui existait déjà côté
`Notifier` avant ce changement.

**Validé en conditions réelles, de bout en bout, sur la VM Kali** : après
déploiement du nouveau binaire, déclenchement d'une vraie détection
persistence (ajout d'une clé dans `~/.ssh/authorized_keys`), le log
confirme `warden_notify_helper: listening for desktop notification
clicks` (connexion réussie, plus d'erreur), puis 3 secondes plus tard
`notification clicked ... incident_id=... action="default"` - et
l'utilisateur a confirmé de visu avoir vu la popup apparaître en haut à
droite de son écran Kali et l'avoir cliquée. C'est la toute première
validation end-to-end réelle (popup affiché + clic + corrélation
d'incident) de tout le projet, sur une vraie session graphique.

## Vision GUI de l'utilisateur (à garder en tête, pas encore commencé)

Décrite explicitement par l'utilisateur : une appli GUI **séparée** du
démon (démon = root, GUI = utilisateur normal), qui apparaît dans le menu
applications/recherche du DE (fichier `.desktop`), montre l'état/historique,
permet des actions live (quarantaine manuelle, whitelist, changement de
mode). Les notifications desktop doivent être **actionnables** : cliquer
dessus ouvre la GUI directement sur le détail de cet incident précis, puis
on peut revenir au tableau de bord et naviguer vers d'autres menus.

Trois prérequis côté démon identifiés (pas encore construits) avant de
pouvoir attaquer la vraie GUI :
1. **Socket de contrôle** (`/run/warden/control.sock`) - la GUI doit
   pouvoir interroger le démon root et déclencher des actions. Bien
   restreindre les permissions à l'utilisateur cible.
2. **Notifications actionnables** - `Notifier` ne fait actuellement que
   `Notify()` fire-and-forget. Il faudra écouter le signal D-Bus
   `ActionInvoked` du serveur de notifications et faire le lien avec
   l'ID de l'incident correspondant.
3. **Historique persistant des events** - actuellement chaque détection
   part dans les logs journald uniquement. Il faut un stockage
   (SQLite ou JSONL) alimenté par le dispatcher pour que la GUI ait
   quelque chose à interroger.

Toolkit GUI pas encore tranché - GTK4/libadwaita pressenti pour un look
natif GNOME, à confirmer quand on y sera vraiment.

**Branding — fait et validé par l'utilisateur.** 4 pistes explorées via
un canvas de design (bouclier plein+serrure, contour minimal, écrou
hexagonal "clin d'œil Rust", lockup+palette). L'utilisateur a choisi :
- **Logo officiel** = concept 1 "Solid + Keyhole" (bouclier rouge plein,
  serrure ambre au centre) → `branding/logo.svg` + `branding/logo.png`.
- **Bannière** = concept 4 "Lockup" (le logo + wordmark "WARDEN" en
  JetBrains Mono + tagline "AUTONOMOUS LINUX EDR") → `branding/banner.svg`
  + `branding/banner.png`.

Palette retenue : `#8c1f1b` (fond de tuile), `#c33a2e` (bouclier),
`#d9a441` (accent ambre/serrure), `#101114` (fond sombre). Les 4 concepts
explorés restent dans `branding/` sous leurs noms d'origine
(`1-solid-keyhole`, `2-outline`, `3-rustnod`, `4-lockup`) pour référence/
archivage. Pas encore fait : export multi-résolutions (16/32/48/64/128/256
px) pour l'icône d'appli GNOME/KDE - à faire quand la GUI sera vraiment
attaquée, pas urgent maintenant.

## GUI, socket de contrôle, exceptions, scan à la demande — faits (session du 22 août, pas encore committés au moment d'écrire ceci)

Les 3 prérequis GUI listés dans la section précédente sont faits : socket
de contrôle (`warden-core/src/control.rs` + `warden-common/src/
control_protocol.rs`, `/run/warden/control.sock`, 0600 chowné à
`target_user`), notifications actionnables (voir plus haut, résolu via
`warden-notify-helper`), historique persistant (`HistoryStore`, déjà
documenté plus haut). `warden-gui` (GTK4) existe et consomme le socket.
Nouveau système d'exceptions ancré SHA-256 (`warden-common/src/
exceptions.rs`, `/etc/warden/exceptions.toml`), jamais modifiable par le
démon ni par le socket - uniquement via `warden --add-exception`/
`--remove-exception` en `pkexec`. `QuarantineFile`/`RestoreQuarantine`
ont été délibérément exclus du protocole du socket après qu'une revue a
trouvé qu'ils permettaient à n'importe quel process au même uid de
désactiver la protection sans authentification réelle - voir les
commentaires dans `control_protocol.rs`. Scan YARA à la demande
(`warden-core/src/scan.rs`, `warden-yara/src/scan.rs`) ajouté aussi,
report-only par construction. Pas encore committé - faire un commit par
lot logique avant la prochaine coupure de session plutôt que de laisser
~2800 lignes non versionnées.

## Audit red team du 22 août - deux bypass réels trouvés et corrigés

Contexte : l'utilisateur a demandé un audit red team poussé sur cette
même vague de fonctionnalités dans une session séparée ("EDR Rust pour
Linux workstations"), qui a fini par être flaguée pour être allée trop
loin dans l'intensité de l'audit demandé - pas un problème dans le code
produit, qui est resté propre et bien documenté (voir les commentaires de
review déjà présents dans `control_protocol.rs`, `quarantine.rs`,
`process.rs`). Infra de test laissée en place et vérifiée vivante dans
cette session : deux VMs libvirt/KVM (`debian13` locale FR, `ubuntu25.10`
locale EN, toutes deux avec un compte `claude:claude` sudo dédié, warden
installé et actif en Enforce) + un conteneur Docker `warden-redteam`
(Kali) comme poste attaquant. Deux scripts de PoC red team trouvés sur
`debian13` (`/home/claude/test_pkgmgr_spoof.sh`,
`/home/claude/test_ransomware_bypass.sh`) - reproduits et validés dans
cette session, pas juste relus :

**Bypass 1 - `package_manager::is_active()` spoofable par emplacement**
(`warden-common/src/package_manager.rs`). L'ancienne version vérifiait
`comm` ET le basename de `/proc/<pid>/exe`, mais jamais le RÉPERTOIRE du
binaire - `cp /bin/sleep /tmp/apt && /tmp/apt 300 &` satisfait les deux
checks sans être le vrai gestionnaire de paquets. Confirmé exploitable en
direct sur `debian13` : un `/etc/cron.d/redteam_v3` a échappé à la
quarantaine automatique en Enforce pendant que le faux `/tmp/apt`
tournait (`persistence: package manager active, leaving file untouched`
dans le journal). **Fix** : le répertoire de l'exécutable doit en plus
canonicaliser vers un des `SYSTEM_BIN_DIRS` connus (même liste que
`warden-privesc`). Testé : nouveau test unitaire reproduisant exactement
la technique (`decoy_binary_outside_system_bin_dirs_does_not_count_as_active`),
ET revalidé en conditions réelles - build redéployé sur `debian13`,
`test_pkgmgr_spoof.sh` relancé, `ATTACK RESULT: file gone -> quarantined
despite spoofing, bypass NOT effective`.

**Bypass 2 - détecteur ransomware contournable par fork-per-file +
répartition multi-dossiers** (`warden-ransomware/src/detector.rs`). Le
détecteur trackait déjà un compteur par PID ET un compteur par dossier
(ce dernier ajouté lors d'une revue précédente, justement pour contrer le
fork-per-file simple) - mais aucun compteur global tous-PID/tous-dossiers
confondus. Résultat : 8 fichiers par dossier × 6 dossiers surveillés,
chacun avec son propre PID éphémère, reste sous le seuil (15) sur les
deux axes existants alors que 48 fichiers au total sont chiffrés en
quelques secondes. Confirmé exploitable en direct sur `debian13` **après
correction d'un faux négatif du script de test lui-même** : la première
tentative (dossiers anglais `Desktop`/`Downloads`/`Pictures`/`Videos`/
`Music`) donnait 0 fichier restant, mais c'était un faux positif du
test - cette VM est en locale FR (`Bureau`/`Téléchargements`/`Images`/
`Vidéos`/`Musique`), donc 5 des 6 dossiers ciblés par le script n'étaient
simplement pas surveillés. Refait avec les vrais noms localisés : 48/48
fichiers laissés intacts, zéro entrée dans le journal - bypass bien réel.
**Fix** : troisième compteur `recent_writes_global`/
`recent_container_format_writes_global` (clé unique, tous PID/dossiers
confondus), même seuil que les compteurs existants. Testé : 3 nouveaux
tests unitaires (burst simple toujours détecté, technique fork-per-file
multi-dossiers désormais détectée, activité légitime à faible volume
répartie sur plusieurs dossiers toujours laissée tranquille) + workspace
entier (`cargo test --workspace`, `cargo clippy --workspace --all-targets
-- -D warnings`) propre.

**Leçon retenue sur la méthodologie de test elle-même** : un script de
red team qui hardcode des noms de dossiers XDG doit être vérifié contre
la vraie locale de la VM cible avant de faire confiance à un résultat
"pas de détection" - sinon un vrai bypass et un simple dossier non
surveillé sont indiscernables sans creuser.

Les deux binaires corrigés sont redéployés et revalidés sur les DEUX VMs
(build depuis `warden-build:rockylinux`, transfert SFTP vers le compte
`claude`, copie en root sur `/usr/local/bin/warden`, `systemctl restart
warden`) : `test_pkgmgr_spoof.sh` relancé sur `debian13` ET une variante
sur `ubuntu25.10` (`ATTACK RESULT: ... bypass NOT effective` dans les
deux cas), technique fork-per-file multi-dossiers relancée sur les deux
(dossiers localisés FR sur `debian13`, EN sur `ubuntu25.10`) - burst
détecté et 48/48 fichiers quarantinés dans les deux cas, avec des
`affected_paths` qui mélangent bien plusieurs dossiers différents,
preuve que c'est le nouveau compteur global qui a déclenché. Reste à
faire : un nouvel audit red team complet (pas juste ces deux PoC ciblés)
avant de considérer cette vague de fonctionnalités prête.

## Campagne SAST + relecture multi-agents (22 août, soir) — 7 findings critiques corrigés et validés en direct

Suite à l'audit red team ci-dessus, l'utilisateur a demandé une passe SAST
poussée (agent dédié) + une relecture de code anti-régression (6 agents en
parallèle, un par sous-système) sur tout le lot de fonctionnalités non
committé. **36 findings remontés au total**, triés par sévérité réelle
(surface atteignable par un process tournant déjà en tant qu'utilisateur
cible - le modèle de menace réaliste pour un EDR, pas un attaquant distant).
Décision utilisateur : corriger les 7 critiques ce soir, documenter le
reste (HIGH/MEDIUM/LOW) comme backlog pour une session dédiée plutôt que
tout traiter d'un coup.

**Les 7 findings critiques, tous corrigés et validés en direct sur
`debian13`** (build → `cargo test --workspace` + clippy propres → déploiement
→ scénario red team rejoué avec le fix en place, pas juste relu) :

1. **`ebpf-probe/warden-exec` quarantinait le mauvais binaire** - la
   résolution `/proc/<pid>/exe` (ajoutée cette session pour contrer
   l'évasion par symlink) renvoyait l'INTERPRÉTEUR pour un script
   (`/bin/bash`), pas le script - un script flagué en `/tmp` faisait
   quarantiner `/bin/bash` lui-même, cassant le système pour tout le
   monde. **Fix** : résolution du symlink faite directement sur `filename`
   (readlink/canonicalize si `filename` EST un symlink), plus jamais via
   l'état du process live - élimine à la fois la confusion interpréteur/
   script et la race TOCTOU pid-reuse. Testé en direct : script flagué →
   le script est quarantiné, hash de `/bin/bash` inchangé avant/après,
   bash reste fonctionnel ; cas légitime (symlink vers un vrai payload en
   `/tmp`) → le payload réel est bien quarantiné, le symlink intact.
2. **Honeypot ransomware - privesc locale via symlink** -
   `honeypot::provision` ne vérifiait jamais si le dossier PARENT du
   honeypot était un symlink avant de faire `chmod 0755`+`chown` dessus.
   Un process tournant en tant qu'utilisateur cible pouvait remplacer le
   dossier honeypot par un symlink vers `/etc/cron.d` et se faire donner
   la propriété d'un répertoire root par le démon lui-même au redémarrage
   suivant. **Fix** : même refus explicite que pour le fichier honeypot
   (déjà protégé). Testé en direct : symlink `Encrypted_Finances ->
   /etc/cron.d`, redémarrage, `/etc/cron.d` reste `755 root:root`
   inchangé, warning loggé, le honeypot se re-provisionne normalement une
   fois le symlink retiré.
3. **Honeypot énumérable par préfixe fixe** (trouvé par le SAST, pas dans
   les 7 "critiques" mais corrigé en même temps par cohérence) -
   `Confidential_Backup_<seed>`/`Banque_<seed>` : le préfixe public et
   fixe rendait tout l'aléatoire du suffixe inutile face à un glob. **Fix** :
   nom entier (adjectif+nom) tiré d'une combinatoire de mots-thèmes
   (15x15, décorrélée pour le honeypot `$HOME` vs les honeypots par
   dossier) dérivée du seed - ferme le cas trivial (un seul grep), honnête
   dans les commentaires sur le fait que ça ne ferme pas le cas d'un
   attaquant motivé prêt à énumérer les 225 combinaisons.
4. **Résolution XDG non validée - bypass Downloads + DoS quarantaine** -
   `xdg::resolve_dir` faisait confiance sans limite à
   `~/.config/user-dirs.dirs` (fichier appartenant à l'utilisateur cible),
   permettant de faire pointer un dossier surveillé vers `/` entier.
   **Fix** : refuse explicitement le cas `/` exact (aucune config XDG
   légitime ne pointe jamais littéralement sur la racine), retombe sur le
   défaut sûr avec un warning. Testé en direct : `XDG_DOWNLOAD_DIR="/"` →
   warning loggé 3x (une fois par module qui résout Downloads), aucun
   module ne watch `/`, `Téléchargements` simplement absent de
   `watch_dirs` au lieu de planter ou tout surveiller. Limite documentée
   et assumée : rediriger vers un AUTRE chemin (pas `/`) pour faire
   disparaître le vrai Downloads du radar reste possible - tension
   inhérente avec le support légitime des locales/points de montage
   personnalisés, pas résolue ce soir.
5. **Bypass permanent du privesc via le cache `already_flagged`** - un
   setuid déposé pendant qu'un vrai gestionnaire de paquets tourne
   (fenêtre légitime) était suppressé UNE FOIS puis plus jamais
   réévalué, même après la fin de l'update - porte dérobée root
   persistante jamais détectée en Enforce. **Fix** : `handle_system_binary`/
   `handle_new_file` retournent maintenant `(event, sticky)` - seule
   l'exemption (`is_exempt`) reste permanente, "package manager actif"
   n'est plus jamais sticky, donc réévalué à chaque tick (2s). Testé en
   direct : backdoor setuid déposé pendant qu'un faux `apt` tourne depuis
   un vrai `SYSTEM_BIN_DIR` (`/usr/local/bin/apt`, seul moyen légitime de
   déclencher `is_active()` depuis le fix du point 6 ci-dessous) → event
   "package manager active" à chaque tick tant qu'il tourne, PUIS dès que
   le faux apt est tué, le tick suivant tente réellement l'action (voir
   point 7, un second bug caché découvert PENDANT ce test).
6. **`package_manager::is_active()` spoofable par emplacement** (détail
   complet plus haut, retrouvé confirmé) - déjà fixé et redéployé plus
   tôt dans la soirée, revalidé une fois de plus par le test du point 5.
7. **Socket de contrôle - DoS mémoire qui tue tout le démon** -
   `AsyncBufReadExt::lines()` n'avait aucune limite de taille de ligne ;
   un client au même uid pouvait streamer sans `\n` jusqu'à l'OOM du
   process `warden` entier (les 4 modules cœur partagent l'adresse
   process). **Fix** : `read_capped_line` (lecture octet par octet sur un
   `BufReader` déjà tamponné, donc pas de coût syscall réel), plafond
   64KiB, erreur (connexion fermée) au-delà. 3 tests unitaires via
   `tokio::io::duplex` (ligne normale, EOF propre, dépassement du
   plafond).
8. **`ProtectSystem=strict` disparu du service systemd** - le démon root,
   avec ses capacités élargies (voir plus bas), n'avait plus aucun
   confinement filesystem. **Fix** : directive restaurée + `RuntimeDirectory=warden`
   (pour `/run/warden`, tmpfs recréé à chaque démarrage) + génération d'un
   drop-in `/etc/systemd/system/warden.service.d/10-paths.conf` par
   `install.sh` (calculé à l'installation : `$STATE_DIR`, le `$HOME` de
   l'utilisateur cible, `/tmp`/`/var/tmp`/`/dev/shm`, les dossiers
   binaires système, les dossiers `UnitDir` de persistence - chaque entrée
   préfixée `-` pour ignorer un chemin absent selon la distro). Vérifié
   par `systemd-analyze verify` (exit 0) et déploiement réel sur
   `debian13` : les 3 services démarrent proprement, honeypots
   provisionnés, socket de contrôle actif.
9. **`install.sh` - écriture root via un chemin `/tmp` prévisible** -
   `2>/tmp/warden-gui-build.log` : classique attaque symlink local (un
   utilisateur non privilégié pré-crée le fichier comme symlink vers une
   cible arbitraire avant que root ne lance l'install). **Fix** :
   `mktemp` à la place. Vérifié : `shellcheck` propre (exit 0) sur tout
   `install.sh`.

**Bug supplémentaire trouvé EN VALIDANT le point 5, pas dans la liste des
7 initiaux mais critique et corrigé dans la foulée** : sous
`ProtectSystem=strict` fraîchement activé (point 8), `rename()` entre
`/tmp` et le dossier de quarantaine échoue maintenant systématiquement
(chaque entrée `ReadWritePaths=` devient son propre bind mount, donc
`/tmp` et `/var/lib/warden` paraissent être des devices différents au
noyau même si c'est le même filesystem physique) - `Quarantine::take`
retombe donc TOUJOURS sur son fallback `fs::copy`, qui préserve les bits
de permission de la source, y compris setuid/setgid - bloqué par
`RestrictSUIDSGID=true` (déjà présent dans l'unit, pas ajouté ce soir).
Résultat : mettre en quarantaine un backdoor setuid échouait en boucle
avec `error=copying ... to quarantine`, silencieusement, à chaque tick -
exactement le scénario que le point 5 vient de corriger. **Fix** :
nouvelle fonction `Quarantine::copy_contents_without_preserving_mode`
(copie le contenu à la main, laisse le mode par défaut de
`File::create` - jamais setuid - sur la copie en quarantaine, plutôt que
`fs::copy` qui tente de reproduire le mode source). Testé (nouveau test
unitaire + revalidé en direct après redéploiement) : le fichier setuid
finit bien par disparaître/être neutralisé une fois retesté.

**Findings HIGH/MEDIUM restants (documentés, pas corrigés ce soir)** -
retrouvables dans les rapports complets des agents SAST + code-review de
cette session, à traiter dans une session dédiée avant de considérer
cette vague de fonctionnalités prête pour la prod :
- TOCTOU rescan-by-path dans `warden-yara::fanotify_monitor` et dans
  l'échantillonnage d'entropie `warden-ransomware::fanotify_monitor`
  (réouverture par chemin au lieu d'utiliser le fd de l'event fanotify).
- `pidfd_open` qui échoue (hors "process déjà mort") ne retente plus rien
  du tout - régression par rapport à l'ancien `kill(pid)` best-effort.
- `control::run`'s `accept()` qui échoue une fois tue le listener IPC en
  permanence (DoS complémentaire à celui déjà fixé ce soir).
- Contournement par forgerie de format container (`PK\x03\x04`+ciphertext)
  plus large que documenté : perd le tracking par-PID entièrement, pas
  juste un seuil x3.
- ~~`warden-yara::scan.rs` : pas de vérification symlink sur les racines de
  scan (`StartScan` via le socket peut être pointé dans `/proc` via un
  symlink), pas de plafond de taille de fichier avant `scan_file`.~~
  **fait** (voir "Backlog MEDIUM traité" plus bas).
- ~~Règle YARA `Bash_Dev_Tcp_Reverse_Shell` contournable par padding
  (`filesize < 65536` gate tout le fichier au lieu de juste borner la
  recherche du motif).~~ **fait** (voir "Backlog MEDIUM traité" plus bas).
- Dossier de règles YARA custom illisible (pas juste absent) fait échouer
  tout le module au lieu de dégrader vers les règles builtin seules.
- **Confirmé en direct** : `StartScan` n'a aucune restriction de chemin -
  connecté au socket en tant qu'utilisateur `test` (uid non-root, exactement
  le modèle de menace), une requête `StartScan(["/root"])` est acceptée
  et exécutée sans broncher (`files_scanned=106` dans `ScanStatus` juste
  après), alors que `test` ne peut lui-même pas lister `/root` (0700
  root:root). Oracle réel : même sans root direct, un process compromis
  au même uid peut faire lire par le démon des fichiers qu'il ne peut pas
  lire lui-même, et en déduire des choses (existence, correspondance à
  une règle YARA) via `ScanStatus`/`History`. Pas de DoS testé (aurait
  fallu un fichier énorme/lent, pas fait pour rester dans le scope
  "sonde", pas "casse la VM").
- `NOTIFY_SOCKET` hérité par `warden-notify-helper`/`warden-gui` malgré
  la chute de privilèges (pas de `env_remove` avant `pre_exec`).
- `--quarantine-file` : le check d'exemption utilise un chemin non
  canonicalisé (contrairement à `--add-exception`/`--remove-exception`).
- TOCTOU sur les permissions du socket de contrôle entre `bind()` et
  `chmod`/`chown` (fenêtre théorique, dépend de l'umask).
- Fichiers manifest de quarantaine pas durcis à `0600` (incohérence avec
  le fix appliqué à `history.rs` dans le même lot).
- Perte d'entrées manifest sous accès concurrent `take()`/`restore()`
  (6 process différents partagent le même répertoire de quarantaine).
- ~~**Confirmé en direct** (installé via `apt install unattended-upgrades`,
  pas juste lu dans le code) : `unattended-upgrade` n'est JAMAIS reconnu
  par `is_active()`, et la cause réelle est plus profonde que la simple
  troncature `comm` soupçonnée au départ - c'est un script Python
  (`#!/usr/bin/python3`), donc `/proc/<pid>/exe` résout vers
  `/usr/bin/python3.13` (l'interpréteur), pas vers
  `/usr/bin/unattended-upgrade` du tout - exactement la même classe de
  bug interpréteur-vs-script que le fix `warden-exec` de ce soir, mais pas
  encore appliquée ici. Testé : un faux setuid déposé pendant qu'un vrai
  `unattended-upgrade --debug` tourne est quarantiné immédiatement au lieu
  d'être suppressé - faux positif garanti sur toute mise à jour
  automatique programmée (`unattended-upgrades` est activé par défaut sur
  Debian/Ubuntu).~~ **fait** (voir "Backlog MEDIUM traité" plus bas).
- Drip-feed lent (rester sous le seuil sur une fenêtre plus longue que
  `burst_window_secs`) contourne toujours les 3 compteurs - limitation
  structurelle inhérente à une détection par fenêtre glissante, pas un
  bug introduit ce soir.
- Kill symbolique pour un process fork-per-file déjà mort au moment de la
  détection (la quarantaine des fichiers reste le vrai mécanisme de
  protection dans ce cas, pas le kill).

## Backlog HIGH traité (22 août, suite) - 2 TOCTOU + l'oracle StartScan

Sur directive explicite de l'utilisateur ("traite le backlog HIGH, surtout
les deux TOCTOU et l'oracle StartScan"), 3 findings HIGH corrigés,
testés, et en cours de validation live :

**TOCTOU `warden-yara::fanotify_monitor`** - le code relisait le fichier
en réouvrant par CHEMIN (`scanner.scan_file(&path)`) après avoir résolu
ce chemin depuis le fd de l'event fanotify, jetant ce fd au passage. Entre
l'event `FAN_CLOSE_WRITE` et la réouverture, un attaquant avec accès
écriture au dossier surveillé peut substituer le contenu (ou un symlink) -
faisant scanner à root un contenu différent de ce qui a réellement été
fermé. **Fix** : nouvelle fonction `read_via_fd` (dup(2) du fd de l'event,
lecture complète via ce dup, jamais de réouverture par chemin) + bascule
de `scanner.scan_file(path)` vers `scanner.scan(&bytes)` (existe déjà dans
l'API yara-x, scanne des données en mémoire). Nécessite `libc` en
dépendance directe de `warden-yara` (déjà dans le workspace, juste pas
déclaré dans ce crate).

**TOCTOU `warden-ransomware::fanotify_monitor`** - exactement le même
défaut, sur le chemin d'échantillonnage d'entropie ("matches
`warden-yara`'s own fanotify listener... works reliably" disait
l'ancien commentaire - vrai uniquement parce que warden-yara avait
exactement le même bug à l'époque, pas parce que réouvrir par chemin
était sûr). **Fix** : même schéma, `read_sample_via_fd` (dup + lecture
bornée à `sample_bytes`, pas tout le fichier - direction opposée à YARA
qui a besoin du contenu complet pour le matching de règles).

**Oracle `StartScan`** (confirmé en direct la nuit dernière : `test`
demandait un scan de `/root` et le démon le faisait, alors que `test` ne
peut pas lire `/root` lui-même) - **fix** : `control::run`/
`handle_connection` reçoivent maintenant `target_home: PathBuf` (déjà
résolu dans `main.rs`, juste jamais passé jusqu'ici), et
`is_scannable_path` refuse toute requête `StartScan` dont un chemin ne
canonicalise pas sous `target_home` OU `/tmp` (déjà lisible/inscriptible
par n'importe quel utilisateur local, déjà surveillé en direct par YARA -
pas un nouveau privilège). Le placeholder du champ de saisie GUI
(`/home/you/Downloads, /tmp, ...`) correspondait déjà exactement à ce
périmètre, aucun changement nécessaire côté `warden-gui`.

Testé : `cargo test --workspace` + `cargo clippy --workspace --all-targets
-- -D warnings` propres (nouveaux tests : `is_scannable_path` refuse
`/root`/`/etc`, accepte le home et `/tmp`).

**Validé en direct sur les deux VMs** : `StartScan(["/root"])` en tant
qu'utilisateur `test` → refusé (`path not allowed`) ; `StartScan` sur son
propre `Documents` → toujours accepté. Non-régression fonctionnelle
confirmée pour les deux TOCTOU corrigés : reverse shell déposé → toujours
détecté et quarantiné par YARA sur les deux VMs ; burst de 16 fichiers
haute-entropie (avec le seed de baseline plaintext requis par
`require_directory_baseline`, oublié puis corrigé dans le test lui-même
sur `ubuntu25.10` - pas une vraie régression, juste un test mal formé la
première fois) → 15-16/16 fichiers quarantinés sur les deux VMs.

## Backlog MEDIUM traité (22 août, suite 3) - oracle StartScan résiduel, padding YARA, unattended-upgrades

Sur directive explicite de l'utilisateur ("commence le backlog MEDIUM"),
3 findings MEDIUM corrigés, testés en Docker, et validés en direct sur
les VMs :

**Oracle/DoS résiduel `StartScan` (`warden-yara::scan.rs`)** - deux trous
distincts dans `scan_paths`/`walk` : (1) le check `is_symlink()` existant
ne s'appliquait qu'aux entrées *découvertes pendant* la marche d'un
répertoire, jamais à la racine `root` elle-même - une racine de scan qui
est elle-même un symlink (vers `/proc` ou ailleurs) passait donc au
travers du filtre `is_excluded` (qui ne voit que le chemin littéral du
symlink, jamais sa cible) et était suivie sans broncher ; (2) aucun
plafond de taille de fichier avant `scanner.scan_file(&path)` - un seul
fichier énorme (image disque de VM, base de données, log multi-Go)
pouvait bloquer un thread de scan indéfiniment. **Fix** : `scan_paths`
vérifie maintenant `std::fs::symlink_metadata(root)` avant d'appeler
`walk` sur chaque racine ; `walk` lit `entry.metadata().len()` et ignore
tout fichier au-dessus de `MAX_FILE_SIZE_BYTES` (100 Mo) sans le scanner.
3 nouveaux tests (`a_symlinked_scan_root_is_not_followed`,
`a_real_directory_root_is_still_scanned_normally`,
`a_file_larger_than_the_size_cap_is_skipped_rather_than_scanned` - ce
dernier utilise un fichier sparse via `set_len` pour ne pas écrire 100 Mo
réels à chaque run de test).

**Règle YARA `Bash_Dev_Tcp_Reverse_Shell` contournable par padding** - la
condition `filesize < 65536` exemptait le fichier *entier* dès qu'il
dépassait 64 Ko, donc un vrai reverse shell fonctionnel restait détecté
tant qu'il faisait moins de 64 Ko, mais un attaquant pouvait garder le
payload intact et juste ajouter du contenu de bourrage après (commentaire,
here-doc, n'importe quoi que bash n'exécute jamais) pour repasser au-dessus
du seuil et faire ignorer le scan entièrement - payload inchangé, toujours
fonctionnel, mais silencieusement plus détecté. **Fix** : remplacé
`filesize < 65536` par `$tcp_redir in (0..65536)` / `$udp_redir in
(0..65536)` / `$exec in (0..65536)` (syntaxe supportée par yara-x,
confirmée en inspectant les tests du parser vendored dans le cache Cargo)
- borne désormais *où* les motifs doivent apparaître (toujours dans les
premiers 64 Ko) plutôt que d'exempter le fichier entier une fois un seuil
de taille dépassé. Nouveau test de non-régression
`still_flags_a_genuine_reverse_shell_padded_past_the_old_filesize_cutoff`
(payload réel + bourrage jusqu'à 70 Ko, doit toujours matcher).

**`unattended-upgrade` jamais reconnu par `is_active()`** - cause
confirmée : script Python (`#!/usr/bin/python3`), donc `/proc/<pid>/exe`
résout vers l'interpréteur (`/usr/bin/python3.13`), jamais vers le script
lui-même. **Fix** : `is_active()` tente maintenant un fallback quand
`exe_name` est un interpréteur connu (`is_known_interpreter` : `python3`
ou `python3.NN`) - il lit `/proc/<pid>/cmdline`, prend `argv[1]` (le
chemin du script, toujours en première position après l'interpréteur pour
une ligne shebang simple sans indirection `env`) via
`interpreted_script_path`, et applique à *ce* chemin les deux mêmes
vérifications que `exe` (nom connu ET répertoire canonicalisant vers
`SYSTEM_BIN_DIRS`) - un `python3 /tmp/evil` qui prétend s'appeler
"unattended-upgrade" via `argv` ne peut toujours pas faire canonicaliser
`/tmp` en dossier système. Nouveaux tests unitaires
(`recognizes_versioned_python_interpreter_names`,
`interpreted_script_path_reads_argv1_from_cmdline`,
`interpreted_script_path_returns_none_when_there_is_no_second_argv`).
**Validé en direct sur `debian13`** : capture du `comm`/`exe`/`cmdline`
réels d'un `unattended-upgrade --debug --dry-run` en cours d'exécution -
`COMM=unattended-upgr`, `EXE=/usr/bin/python3.13`,
`CMDLINE=/usr/bin/python3|/usr/bin/unattended-upgrade|--debug|--dry-run|`
- confirme exactement la forme que le fix suppose (et que l'ancien code,
qui ne vérifiait que le basename brut de `exe`, ne pouvait jamais
reconnaître).

Testé : `cargo build --workspace` + `cargo clippy --workspace
--all-targets -- -D warnings` propres + `cargo test --workspace` (57
tests, tous verts, y compris les 8 nouveaux ci-dessus). Déployé et
redémarré proprement sur `debian13` et `ubuntu25.10` (`systemctl
is-active` → `active` sur les deux, logs de démarrage sans erreur pour
les 4 modules).

Note utilisateur en cours de session : `/usr/bin` est refusé par
`StartScan` ("path not allowed (must be under your home directory or
/tmp)") - **c'est le comportement voulu**, hérité du fix de l'oracle
`StartScan` (backlog HIGH, section précédente), pas de ce lot MEDIUM. À
laisser tel quel sur confirmation explicite de l'utilisateur.

## Backlog MEDIUM/LOW traité en totalité (22 août, suite 4)

Sur directive explicite de l'utilisateur ("fait toute la ligne
medium/low"), les 9 findings restants du backlog HIGH/MEDIUM/LOW sont
tous corrigés, testés en Docker, et validés en direct sur les deux VMs :

**`pidfd_open` qui échoue ne signalait plus rien du tout**
(`warden-common::process`) - régression confirmée par rapport à l'ancien
`kill(pid)` best-effort : n'importe quel échec de `pidfd_open` (pas
seulement "process déjà mort") faisait abandonner `stop_then_kill` sans
envoyer aucun signal. **Fix** : nouvelle fonction `raw_kill` (kill par
PID brut, moins sûr face au PID reuse que la voie pidfd mais strictement
meilleur que rien) utilisée en fallback quand `pidfd_open` échoue. Testé
directement (`raw_kill_fallback_actually_terminates_a_real_child_process`)
- pas de moyen portable de forcer un vrai échec `pidfd_open` sur un
process réellement vivant depuis un test unitaire, donc le fallback est
testé isolément, même logique que les tests `pidfd_open_*` existants.

**`control::run`'s `accept()` tuait le listener IPC en permanence**
(`warden-core::control`) - une seule erreur (`EMFILE`/`ENFILE` typiquement)
propagée via `?` terminait toute la boucle de contrôle pour le reste de
la vie du démon. **Fix** : boucle de retry avec backoff croissant
(plafonné à 2s), même schéma que le retry déjà en place sur
`fanotify::read_events`.

**TOCTOU sur les permissions du socket de contrôle** entre `bind()` et
`chmod`/`chown` (`warden-core::control`) - **fix** : `umask(0o077)` posé
juste avant `bind()`, restauré juste après - le socket naît déjà
non-accessible au groupe/others, sans fenêtre. **Validé en direct sur les
deux VMs** : `stat` sur `/run/warden/control.sock` juste après démarrage
→ `600 test:test` sur les deux.

**Contournement par forgerie de format container plus large que
documenté** (`warden-ransomware::detector`) - `observe_container_format_write`
ne trackait QUE par répertoire et globalement, aucun compteur par-PID,
contrairement à `observe_high_entropy_write`. Un process non-forké qui
forge une signature ZIP/PDF sur chaque fichier chiffré bénéficiait donc
d'un seuil 3x plus faible que prévu simplement parce que le signal le
plus direct (par-PID) manquait totalement sur ce chemin. **Fix** :
compteur `recent_container_format_writes_by_pid` ajouté au même seuil
élevé que les deux autres, `files_for_pid`/`forget` mis à jour pour le
fusionner - restaure aussi l'attribution correcte pour la réponse
(quarantaine). Testé
(`container_format_burst_from_a_single_pid_is_attributed_to_that_pid`).

**Dossier de règles YARA custom illisible faisait échouer tout le
module** (`warden-yara::rules`) - `read_dir` sur un dossier existant mais
illisible (ACL cassée, montage réseau) propageait via `?`, faisant
échouer `compile()` entièrement - même les règles builtin. Scénario
plausible en prod : `custom_rules_dir` hors du périmètre
`ReadWritePaths=` de `ProtectSystem=strict` renvoie `EACCES` même à root
au niveau du mount namespace, pas des permissions DAC classiques (donc
pas reproductible par un simple `chmod 000` en root dans un test unitaire
- documenté honnêtement plutôt que simulé). **Fix** : dégrade vers
builtin-only avec un `warn!`, comme le cas "dossier absent" déjà géré.
Testés : dossier absent (`nonexistent_custom_rules_dir_falls_back_to_builtin_only`)
et dossier valide avec une règle custom
(`a_valid_custom_rule_file_loads_alongside_builtins`) - aucun test
n'existait avant pour le chemin custom-rules-dir du tout.

**`NOTIFY_SOCKET` hérité par `warden-notify-helper`/`warden-gui` malgré
la chute de privilèges** (`warden-common::notify`) - systemd pose
`NOTIFY_SOCKET` dans l'environnement du process root ; sans
`env_remove`, le helper (privilèges tombés vers l'utilisateur cible) en
héritait, lui donnant un canal pour envoyer de faux `WATCHDOG=1`/
`READY=1` à l'unité systemd de ce démon root. **Fix** :
`command.env_remove("NOTIFY_SOCKET")` avant le `pre_exec` de drop de
privilèges - `warden-gui` (lancé PAR le helper, jamais directement par
`warden-core`) en hérite naturellement l'absence. **Validé en direct sur
`debian13`** : déclenché une vraie détection YARA (reverse shell déposé),
capturé `/proc/<pid du helper>/environ` → `NOTIFY_SOCKET` absent, contre
présent dans l'environ de `warden` lui-même (`/run/systemd/notify`) pour
comparaison.

**`--quarantine-file` : check d'exemption sur un chemin non-canonicalisé**
(`warden-core::main`) - contrairement à `--add-exception`/
`--remove-exception` (qui canonicalisent avant de comparer), un chemin
relatif ou avec `..` passé à `--quarantine-file` pouvait faire échouer
silencieusement la reconnaissance d'une exception active existante,
contournant le garde-fou "refuse d'agir sur un chemin exempté". **Fix** :
canonicalisation ajoutée avant `is_exempt`/`quarantine.take`, cohérent
avec le reste du CLI.

**Fichiers manifest de quarantaine pas durcis à `0600`**
(`warden-common::quarantine`) - `manifest.jsonl` et son fichier de
réécriture temporaire (`rewrite_manifest`) n'avaient pas de mode explicite.
**Fix initial** : `.mode(0o600)` sur les `OpenOptions`. **Piège trouvé en
validant en direct** : `.mode()` ne s'applique QUE si `open()` crée
réellement le fichier - un `manifest.jsonl` déjà existant sur `debian13`
(accumulé pendant toute cette session) restait à `644` après le premier
redéploiement, `.mode(0o600)` n'ayant simplement rien à faire sur un
fichier déjà là. **Fix corrigé** : `f.set_permissions(0o600)` réappliqué
explicitement sur le handle déjà ouvert, à chaque appel, même logique que
`Quarantine::new()` pour le dossier lui-même ("ne jamais faire confiance
à ce qui a survécu, toujours la réaffirmer"). **Re-validé en direct sur
les deux VMs après correction** : nouvelle détection déclenchée →
`manifest.jsonl` bien à `600 root:root` sur `debian13` ET `ubuntu25.10`.

**Perte d'entrées manifest sous accès concurrent `take()`/`restore()`**
(`warden-common::quarantine`) - 6 process différents (`warden`,
`warden-exec`, `warden-network`, et chaque module de détection dans son
propre process) partagent le même répertoire de quarantaine sans aucun
verrou. `restore()` lit tout le manifest, déplace le fichier, puis
réécrit le manifest SANS l'entrée restaurée - un `take()` concurrent qui
ajoute une entrée entre cette lecture et cette réécriture se faisait
silencieusement écraser par la réécriture basée sur l'instantané périmé.
Second problème trouvé en marge : `append_manifest` utilisait `writeln!`
directement sur le fichier, ce qui émet DEUX appels `write(2)` séparés
(la ligne JSON, puis le `\n`) - chacun atomique individuellement sous
`O_APPEND`, mais pas la paire, laissant une fenêtre où l'écriture d'un
autre process pouvait s'intercaler entre les deux et corrompre les deux
lignes. **Fix** : verrou `flock(2)` exclusif partagé
(`manifest.lock`, nouveau fichier) posé sur toute la section
lire-modifier-écrire de `restore()` et autour de chaque appel à
`append_manifest` ; `append_manifest` construit la ligne complète
(JSON + `\n`) et l'écrit en un seul `write_all`. Testés :
`concurrent_appends_do_not_lose_or_corrupt_entries` (8 threads × 20
écritures, aucune perdue) et `concurrent_take_during_restore_does_not_lose_the_new_entry`
(reproduit précisément le scénario de perte confirmé) - un `flock` posé
via un `open()` frais par appel se comporte identiquement entre threads
et process séparés, donc ces tests reproduisent fidèlement la course
inter-process réelle.

**Drip-feed lent et kill symbolique pour un process déjà mort** :
confirmés comme limitations structurelles (détection par fenêtre
glissante, quarantaine des fichiers reste la vraie protection dans ce
cas) plutôt que des bugs à corriger - acceptées, documentées, pas de
changement de code.

Testé : `cargo build --workspace` + `cargo clippy --workspace
--all-targets -- -D warnings` propres + `cargo test --workspace` (63
tests, tous verts). Déployé et revalidé en direct sur `debian13` ET
`ubuntu25.10` : socket de contrôle `600`, `Ping`/`Pong` fonctionnel,
détection reverse-shell toujours opérationnelle (quarantaine effective),
`manifest.jsonl`/`manifest.lock` à `600 root:root` sur les deux,
`NOTIFY_SOCKET` absent de l'environnement de `warden-notify-helper`.

## Prochaine session : par où reprendre

Le backlog HIGH/MEDIUM/LOW documenté depuis le début de cette vague est
maintenant **entièrement traité** (7 critiques + 3 HIGH + 12 MEDIUM/LOW,
2 de ces derniers acceptés comme limitations structurelles plutôt que
corrigés). Ce lot a été committé (`89059a0`).

## `install.sh`/`uninstall.sh` validés de bout en bout sur les 4 familles de gestionnaires de paquets + création d'un désinstalleur (23 août)

Plutôt que de tester bêtement les 7 noms de distro un par un, `install.sh`
n'a en réalité que 4 branches de gestionnaire de paquets distinctes
(apt/dnf/pacman/zypper) - chacune validée une fois pour de vrai plutôt
que dupliquée inutilement :

- **apt** (Debian/Ubuntu/Kali/Mint/Pop) - `install.sh` exécuté pour de
  vrai (pas le script de déploiement manuel habituel) sur les deux VMs
  réelles `debian13` et `ubuntu25.10`, y compris le build eBPF complet
  (`warden-exec`/`warden-network`, rustup nightly + bpf-linker déjà en
  place sur ces VMs depuis les sessions précédentes) et la GUI GTK4.
  Détection reverse-shell confirmée fonctionnelle après install sur les
  deux.
- **dnf** (Fedora/RHEL/Rocky/Alma/CentOS) - nouveau
  `docker/Dockerfile.test.fedora` (systemd réel comme PID1, pattern
  repris de `~/ransomshield/docker/Dockerfile.debian`: masquer les
  units matériel-dépendantes inutiles en conteneur, `STOPSIGNAL
  SIGRTMIN+3`, `VOLUME ["/sys/fs/cgroup"]`, `CMD ["/sbin/init"]`).
  `install.sh` exécuté pour de vrai (`cargo`/`rustc` distro via `dnf`,
  eBPF sauté proprement - pas de rustup nightly configuré, comportement
  attendu et documenté dans le script) : build complet workspace + GUI
  GTK4/libadwaita, unit systemd installée et démarrée, détection
  reverse-shell confirmée (fichier quarantiné).
- **pacman** (Arch/Manjaro) - `docker/Dockerfile.test.arch`, même
  validation complète.
- **zypper** (openSUSE Tumbleweed/SLES) - `docker/Dockerfile.test.opensuse`,
  même validation complète.

**Nouveau : `uninstall.sh`** (sur demande explicite) - désinstalleur
propre : arrête/désactive les services AVANT de toucher un fichier (même
raisonnement qu'`install.sh` : persistence surveille activement
`/etc/systemd/system`), retire binaires/units/icônes GUI, et laisse
`/etc/warden` (config) et `/var/lib/warden` (quarantaine, historique,
seed honeypot) intacts par défaut - un fichier quarantiné peut être la
seule copie survivante d'un incident réel. Un `--purge` optionnel
supprime aussi ces deux-là, mais seulement après confirmation explicite
(`yes` tapé, ou `-y`/`--yes` pour l'usage non-interactif). Tous les
chemins agis dessus sont des constantes fixes en tête de script - jamais
construits depuis une variable qui pourrait être vide, pour qu'aucun
`rm -rf` ne puisse jamais s'élargir accidentellement. Ne tente pas de
reconstruire/supprimer les dossiers honeypot dans le `$HOME` de
l'utilisateur (leur nommage est un algorithme dérivé d'un seed
aléatoire dans `honeypot.rs` - le dupliquer en bash serait une
seconde implémentation risquant de diverger silencieusement de la
vraie ; un pattern-match sur des dossiers arbitraires dans un home
réel pour les supprimer automatiquement est aussi le genre de pari
qu'un script de nettoyage ne devrait pas faire) - documenté
explicitement dans le message final plutôt que laissé sous silence.

**SAST** : `shellcheck` propre (exit 0) sur `uninstall.sh`.

**Validé en conditions réelles** (installation réelle → détection réelle
→ désinstallation → vérification qu'il ne reste plus rien → re-exécution
pour prouver l'idempotence → réinstallation pour laisser la machine
protégée) sur :
- Fedora, Arch, openSUSE (conteneurs Docker, `--purge` testé - jetables,
  aucune donnée réelle à perdre).
- `debian13`, `ubuntu25.10` (VMs réelles, **sans** `--purge` - ces VMs
  ont des mois de preuves de tests red-team accumulées dans leur
  quarantaine ; 69 et 73 fichiers respectivement, comptés avant/après
  pour confirmer qu'aucun n'a été perdu par la désinstallation par
  défaut). Les deux VMs ont été réinstallées ensuite via `install.sh`
  pour repartir protégées.

Incident opérationnel en cours de route, pour référence future : la
toute première tentative d'exécuter `install.sh` sur `ubuntu25.10` via
`paramiko.exec_command` (sans `setsid`/`nohup`/`disown`) a subi un
`PipeTimeout` côté client sans que le process distant meure - il a
continué à tourner en arrière-plan, orphelin, pendant plusieurs heures
en parallèle d'une seconde tentative relancée par erreur, gonflant
artificiellement la durée totale sans qu'aucun des deux builds ne soit
réellement bloqué. Leçon retenue : toujours lancer une commande longue
sur une VM distante via `setsid nohup ... & disown` avec sortie
redirigée vers un fichier, jamais en gardant le process attaché à la
session SSH/paramiko elle-même - une commande longue ne doit jamais
dépendre de la survie de la connexion qui l'a lancée.

Lot install/uninstall committé (`f20282f`). README réécrit et committé
(`78cb91c`). `PUSH_TO_GITHUB.txt` et `/home/user/warden.zip` préparés
(zip validé de bout en bout : contenu extrait à froid dans un conteneur
neuf, `install.sh` exécuté depuis cette copie, détection réelle
confirmée - le zip est un livrable autoportant complet).

## `pkexec`/PolicyKit manquant - trouvé en testant la GUI en direct (23 août)

L'utilisateur a testé la GUI en conditions réelles sur `debian13` -
Restore et Switch mode échouaient tous les deux avec "Could not run
pkexec: Aucun fichier ou dossier de ce nom". Cause : `pkexec` (utilisé
par TOUTES les actions authentifiées de la GUI - restore, exceptions,
quarantine manuel, changement de mode, voir `run_pkexec_warden` dans
`warden-gui/src/ui.rs`) n'était installé par aucune branche
d'`install_packages()` - jamais un vrai paquet requis pour BUILD Warden,
seulement pour l'UTILISER une fois installé, donc invisible tant qu'une
machine a déjà un environnement de bureau complet qui l'apporte comme
dépendance (le cas de toutes les vraies machines desktop, mais pas de
cette VM minimale ni des conteneurs de test de cette nuit).

**Piège en corrigeant** : `policykit-1` n'existe plus tel quel sur
Debian 13 (trixie) - scindé en `pkexec` + `polkitd` séparés. Un simple
ajout de `policykit-1` à la liste de paquets aurait fait échouer
`apt-get install` EN ENTIER (un seul nom de paquet introuvable annule
toute la commande), cassant tout l'install sur trixie pour ce détail.
**Fix** : nouvelle fonction `install_polkit_apt()` isolée, essaie
`policykit-1` puis retombe sur `pkexec`+`polkitd`, best-effort (avertit
sans faire échouer le reste de l'install). `polkit` ajouté directement
pour dnf/pacman/zypper - vérifié en direct (requête au dépôt de chaque
distro, pas juste supposé) que c'est le bon nom sur les 3.

**Incident opérationnel en marge** : pour tester le fix proprement,
`pkexec` a été désinstallé de `debian13` pour simuler une machine
neuve - sans prévenir l'utilisateur que c'était fait sur la VM qu'il
testait activement, ce qui a cassé la GUI sous ses yeux pendant le
test. Réinstallé immédiatement. Leçon : une action destructive/perturbatrice
sur une machine que l'utilisateur utilise activement en direct doit être
annoncée AVANT de la faire, même pour un test, même réversible en
quelques secondes.

**Validé en direct sur `debian13`** : `pkexec` désinstallé, vrai
`install.sh` relancé de bout en bout (build complet + `install_polkit_apt`
+ démarrage des 3 services), `pkexec` de retour, détection reverse-shell
toujours fonctionnelle. Un agent d'authentification PolicyKit
(`polkit-kde-authentication-agent-1`) était déjà actif dans la session
KDE Plasma de la VM, confirmant que `pkexec` seul était bien la pièce
manquante. Committé (`4f68624`).

## Prochaine session : par où reprendre

1. Nouvel audit red team complet sur les deux VMs (dans le conteneur
   `warden-redteam`/les VMs uniquement - directive utilisateur : rien
   téléchargé depuis internet/GitHub pour le red team, uniquement des
   paquets `apt` et des outils écrits maison).
2. Régénérer `/home/user/warden.zip` et `install.sh` sur le Bureau si
   d'autres changements de code sont faits (actuellement à jour avec
   `4f68624`, mais à revérifier avant publication finale sur GitHub).
3. Évaluer une détection Sigma simplifiée (YARA fait, voir plus haut).
4. Privesc : capabilities Linux (`setcap`) en complément du SUID/SGID.
5. `cargo-deny` en complément de `cargo-audit` (licences, bans de crates).
6. Module infostealer (lecture des stores de credentials navigateur/SSH/
   cloud CLI) - discuté et scopé avec l'utilisateur (mode notify d'abord,
   pas de blocage synchrone, liste de confiance pour les accesseurs
   légitimes), mais explicitement refusé pour l'instant ("la flemme, on
   fait rien... c'est une défense en plus, pas un remplacement de la
   vigilance humaine"). Ne pas reproposer sans que l'utilisateur relance
   le sujet lui-même.

## Audit externe (issue #1, PR #2, audit "Fable") - analysé, corrigé, validé en direct (23 août)

Le dépôt a été poussé sur GitHub entre-temps (`Spellskite-coding/Warden`).
Un ami a ouvert une issue de sécurité réelle sur le burst detector, une PR
avec un correctif, et fait passer une revue de code plus large ("Fable")
sur l'architecture générale. Les trois ont été lus et vérifiés contre le
code réel avant toute action - pas pris pour argent comptant.

**Issue #1 / PR #2 - burst detector aveugle aux nouveaux répertoires.**
Confirmé exact par lecture directe : `observe_high_entropy_write` et
`observe_container_format_write` retournaient `Verdict::Clean`
immédiatement si `has_baseline()` était faux, court-circuitant même le
compteur global - un répertoire fraîchement créé (jamais vu avec un
contenu en clair) était invisible au burst detector, quel que soit le
nombre de fichiers chiffrés dedans.

La PR proposait un correctif plus fin que l'issue elle-même : compteur
per-pid rendu inconditionnel, deux maps globales séparées (baseline vs
sans baseline) pour éviter un verdict qui dépend de l'ordre d'écriture.
Bonne architecture, mais un défaut réel dans les seuils choisis : la PR
mettait le seuil "sans baseline" à 2x le seuil normal (30 fichiers au
lieu de 15) - ce qui rouvre le bug qu'elle corrige, juste avec un budget
plus grand : un attaquant qui cible systématiquement des répertoires
neufs obtient une allocation double. Repris la structure de la PR (maps
séparées, per-pid inconditionnel) mais avec le MÊME seuil des deux côtés
- pas d'incitation mécanique à préférer les répertoires neufs.

Reproduit en direct sur `debian13` (mode enforce, `test` protégé) :
`mkdir` + 20x `dd if=/dev/urandom` dans un répertoire neuf sous
`Documents/` - AVANT le correctif ça serait passé silencieusement (bug
confirmé par lecture de code, pas re-testé sur l'ancien binaire pour ne
pas perdre de temps). APRÈS : détection déclenchée pile au 15e fichier
(`recent_writes_global_unbaselined`, seuil identique au cas avec
baseline), les 20 fichiers mis en quarantaine. 6 nouveaux tests unitaires
ajoutés dans `detector.rs` (bypass global sans baseline, container-format
sans baseline, per-pid seul, seuils identiques baseline/sans-baseline,
répertoire type Pictures jamais baseliné).

**Fuite mémoire dans le détecteur (trouvé par l'audit "Fable", confirmé
réel).** `record_and_check` purge la map interne d'une clé à chaque écriture
sur cette même clé, mais ne retire jamais la clé externe elle-même une
fois son contenu vidé - un PID qui écrit une fois puis ne revient jamais
(l'écrasante majorité des PIDs sur un poste actif) laisse une entrée
permanente dans `recent_writes_by_pid`. Ajouté `Detector::prune_expired`,
appelé une fois par fenêtre de burst dans la boucle fanotify (throttled,
pas à chaque évènement). Testé : 500 PIDs distincts, un seul appel après
expiration de la fenêtre, la map est vide ensuite.

**Contournement complet de l'auto-quarantine par un utilisateur non
privilégié (audit "Fable", confirmé réel et plus grave que documenté).**
`package_manager::is_active()` ne vérifiait jamais l'UID du processus -
`while :; do /usr/bin/rpm --version >/dev/null; done &` lancé par
n'importe quel compte local suffisait à maintenir `is_active()` à `true`
en continu, sans aucun privilège, suspendant l'auto-quarantine
persistence/privesc en mode Enforce indéfiniment. Ajouté une vérification
d'UID (0 = root, via le propriétaire du répertoire `/proc/<pid>`, pas
`/proc/<pid>/status` - moins cher et pas falsifiable par le processus
lui-même) - chaque cas légitime (apt/dnf/pacman réel, unattended-upgrade,
update-initramfs) tourne déjà en root au moment où ça compte. Testé en
plaçant un faux binaire nommé correctement dans un vrai `SYSTEM_BIN_DIRS`
et en le lançant sous l'uid 65534 ("nobody") - passe tous les autres
checks, rejeté uniquement par le nouveau contrôle d'UID.

**Nom de fichier des honeypots fixe malgré le dossier randomisé (audit
"Fable", confirmé réel).** Le dossier parent était bien randomisé par
seed (`Confidential_Backup_<hex>`, 225 combinaisons), mais le fichier
*à l'intérieur* était toujours littéralement `passwords_export.csv` ou
`releve_compte.csv` - un `find / -name passwords_export.csv` trouve tous
les honeypots sur la machine sans jamais avoir besoin du seed ni de
connaître le schéma de nommage du dossier. Ajouté deux pools de noms de
fichiers plausibles (`HONEYPOT_FILENAMES`, `HOME_HONEYPOT_FILENAMES`),
dérivés du seed avec une rotation indépendante de celle du nom de
dossier. Testé en direct sur `debian13` : honeypot re-provisionné sous
`Documents/Classified_Contracts/vault_export.csv`, écriture dedans
détectée et mis en quarantaine normalement (`honeypot touched:
.../vault_export.csv`). Note : après mise à jour, l'ancien fichier au nom
fixe reste orphelin dans le même dossier (pas de logique de migration
ajoutée exprès - même raisonnement que pour les autres artefacts de
honeypot déjà documenté : pas grave, pas de nettoyage automatique risqué).

**Échantillonnage d'entropie contournable en préfixant le fichier (audit
"Fable", confirmé réel).** `read_sample_via_fd` ne lisait que les 8 Kio
au tout début du fichier (offset 0). Un ransomware préfixant chaque
fichier chiffré d'un en-tête en clair de 8 Kio (ou laissant le début du
fichier original intact) passait systématiquement sous
`entropy_threshold`, et pire, chaque écriture de ce type empoisonnait la
baseline du répertoire via `note_plaintext_activity`. Remplacé par
`sample_entropy_via_fd` : échantillonne 3 zones réparties (début, milieu,
fin), retourne l'entropie MAXIMALE des trois (pas la moyenne, qui serait
elle aussi contournable en diluant une zone à haute entropie avec du
remplissage). Le sniffing de format container (ZIP/PDF/JPEG) reste basé
sur le premier chunk (offset 0), où vivent les magic bytes de toute façon.

**Sortie propre d'un module = perte de protection silencieuse (audit
"Fable", confirmé - non atteignable aujourd'hui mais le type le
permettait).** Chaque boucle de module est un `loop {}` sans `break`, donc
un retour `Ok(())` propre n'était pas atteignable en pratique - mais le
code le traitait comme un arrêt normal (`exit(0)`) si jamais ça arrivait,
et `Restart=on-failure` de systemd ne redémarre PAS sur un exit 0. Corrigé
: un retour `Ok(())` d'une boucle de module est maintenant traité comme
fatal (exit non-zéro), pour que `Restart=on-failure` fonctionne quelle que
soit la raison de l'arrêt. Ajouté un `WatchdogSec=30` avec ping
périodique côté `main.rs` (`sd_notify::watchdog_enabled()`), et
`StartLimitIntervalSec=120`/`StartLimitBurst=10` pour laisser une vraie
chance de redémarrage après un échec transitoire sans non plus
crash-looper indéfiniment.

**Durcissement systemd supplémentaire (audit "Fable") - une régression
réelle trouvée en la testant en direct, corrigée avant de la garder.**
Ajouté `RestrictAddressFamilies=AF_UNIX` et `ProtectProc=invisible` - les
deux validés en direct (socket de contrôle, détection des 4 modules,
lecture `/proc/<pid>` d'autres utilisateurs via `CAP_SYS_PTRACE` pour
`package_manager`). `MemoryDenyWriteExecute=true` a été essayé aussi,
mais **casse complètement le module yara** : `yara-x` compile les règles
via un JIT `wasmtime`, qui a besoin de rendre une page mémoire
inscriptible PUIS exécutable - exactement ce que cette directive bloque.
Résultat en direct : le module yara panique au démarrage ("WASM module is
not valid: unable to make memory executable"), ce qui - combiné au fait
qu'un panic de module est fatal pour tout le démon - a fait entrer
`warden.service` en crash-loop toutes les ~2s. Directive retirée avant de
committer. Leçon confirmée une fois de plus : chaque directive de
durcissement doit être testée en démarrant vraiment le service et en
vérifiant que les 4 modules rapportent "ready", pas seulement que le
process a démarré.

**Ce qui a été délibérément documenté plutôt que codé (limitations
d'architecture, pas des bugs).**
- Le mode Enforce ne peut que constater après coup (fanotify
  `FAN_CLASS_NOTIF`, pas `FAN_CLASS_CONTENT`/permission events) - un vrai
  blocage synchrone existe côté kernel mais avec un risque de deadlock et
  un coût de perf différents ; pas de changement d'architecture pour
  aujourd'hui, seulement à documenter honnêtement dans le README (le
  README actuel dit déjà "kills/quarantines it immediately", ce qui est
  globalement correct - la détection est quasi-instantanée à l'échelle
  humaine même si techniquement post-hoc).
- Le seuil de burst est un débit (N fichiers / fenêtre), pas un volume
  cumulatif long terme - un ransomware très lent (1 fichier/s) resterait
  sous le radar indéfiniment. Un vrai compteur cumulatif long terme
  demanderait de la persistance entre redémarrages pour ne pas être
  trivialement contournable (redémarrer le service reset le compteur) -
  hors scope pour cette passe, les honeypots restent le filet de sécurité
  pour ce cas.
- Coût CPU/fd du double mark fanotify filesystem-wide (ransomware + yara)
  sur une machine très active en écriture - déjà `FAN_UNLIMITED_QUEUE`,
  pas d'autre optimisation évidente sans changer d'approche (marks
  par-répertoire, qui casserait la détection des sous-répertoires créés
  après coup).
- `ReadWritePaths` du service systemd : vérifié, déjà strictement le
  minimum nécessaire (correspond exactement à ce que `package_manager`/
  `quarantine`/`honeypot` touchent réellement) - pas une vraie régression
  malgré ce que l'audit "Fable" laissait entendre.
- Symlink loop dans `warden-ransomware/src/baseline.rs::seed()` - **vérifié
  et non reproductible** : `DirEntry::metadata()` sur Unix utilise `lstat`
  (ne suit pas les symlinks), confirmé par un test Rust minimal compilé
  dans le conteneur de build (`entry.metadata().is_dir()` retourne `false`
  pour un symlink, même pointant vers un répertoire réel). L'audit avait
  tort sur ce point précis - noté pour ne pas perdre de temps dessus si ça
  revient.
- Ratio commentaires/code élevé (~26%, relevé par l'audit) - décision
  délibérée de ne pas réduire : les commentaires de ce projet portent
  presque tous une justification de sécurité durement acquise (un bypass
  trouvé en red-team, une raison précise pour un choix de seuil...), pas
  du bruit. Retirer ce contexte pour améliorer un ratio ferait perdre
  exactement l'information qui a le plus de valeur pour un futur lecteur
  ou contributeur.

**Hygiène du dépôt - ajouté ce qui était mécanique et peu risqué.**
`.github/workflows/test.yml` (build+test+clippy+cargo-audit sur tout le
workspace, y compris `warden-gui` avec les dépendances GTK4/libadwaita -
plus large que le `.yml` de la PR, qui ne couvrait que
`warden-ransomware`). `--locked` ajouté aux trois invocations de `cargo
build` dans `install.sh`. `cargo fmt --all -- --check` délibérément PAS
ajouté à la CI : le style existant du projet (lignes larges, signatures
sur une ligne) ne correspond pas aux réglages par défaut de rustfmt, et
personne n'a demandé de reformater tout le dépôt - une CI rouge dès le
premier push serait pire que pas de check du tout.

**Validation.** `cargo build/clippy -D warnings/test --workspace --locked`
propres dans le conteneur Rocky Linux (72 tests, tous verts). `shellcheck`
propre sur `install.sh`/`uninstall.sh`. Testé en direct de bout en bout
sur `debian13` (KDE Plasma, utilisateur protégé `test`) : upgrade en place
via `install.sh` (piège trouvé : `TARGET_USER` reprend `$SUDO_USER`, donc
relancer `sudo ./install.sh` en étant connecté en SSH sous un autre compte
que l'utilisateur protégé écrase la config pour le mauvais utilisateur -
rattrapé avant que le drop-in systemd soit réécrit, relancé avec
`WARDEN_TARGET_USER=test` explicite), reproduction du PoC exact de
l'issue #1 (corrigé), honeypot au nouveau nom de fichier (détecté),
restore-from-quarantine (toujours fonctionnel). Matrice dnf/pacman/zypper (Fedora/Arch/openSUSE, conteneurs
systemd-as-PID1) relancée avec le code à jour : les trois passent propre
(`install.sh` exit 0, service `active`, `uninstall.sh --purge` exit 0,
aucun résidu - binaires/units/`/etc/warden`/`/var/lib/warden` tous
absents après). Les 4 familles de gestionnaires de paquets sont donc
validées avec le code d'aujourd'hui : apt en direct sur la VM (le seul
test poussé jusqu'au bout fonctionnel, pas juste installation/suppression
- PoC, honeypot, restore), dnf/pacman/zypper via la matrice Docker
(installation/démarrage/suppression propres, pas de test fonctionnel
poussé aussi loin que sur la VM - couverture jugée suffisante puisque le
code Rust est strictement le même binaire partout, seule la partie
gestionnaire de paquets d'`install.sh` change réellement d'un OS à
l'autre).
