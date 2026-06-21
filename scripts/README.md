# Switch ambiente ASF: test vs produzione

Script per far girare il sistema (daemon + hook + agente) in modalità **test**,
così le scritture finiscono su `asf_test.db` invece che sul DB di produzione
`asf_local.db`. Vedi anche la doc di tesi "04 Switch ASF_ENV isolamento DB di test".

## Premesse importanti

- `ASF_ENV` si legge **una sola volta all'avvio** di ogni processo. Non si cambia a runtime.
- I daemon (Rust + Python hook daemon) sono **condivisi via socket**: se ne è già
  attivo uno in prod, una nuova sessione test si riaggancia a quello e scrive in prod.
  Per questo gli script killano i daemon prima di cambiare ambiente.
- Non mischiare una sessione prod e una test contemporaneamente: vince il daemon attivo.
- Il bottone test/prod della dashboard cambia solo **quale DB leggi**, non dove il
  sistema scrive. Per una vista coerente: sistema in test + bottone su test.

## Gli script

| Script | Cosa fa |
|--------|---------|
| `asf-status.sh` | Sola lettura: daemon attivi + conteggi righe in prod e test. |
| `asf-test.sh`   | Killa i daemon, pulisce i socket, avvia `claude` con `ASF_ENV=test`. |
| `asf-prod.sh`   | Killa i daemon e pulisce; con `--launch` riavvia `claude` in prod. |

## Procedura: verificare il comportamento in test

1. Stato di partenza (opzionale, per avere un riferimento):

       ./scripts/asf-status.sh

2. Avvia la sessione di test (sostituisce la shell con claude in modalità test):

       ./scripts/asf-test.sh

3. Dentro quella sessione Claude Code, fai eseguire un comando qualsiasi
   (es. chiedi `ls`, oppure digita `!ls`). L'hook scatta, i daemon ripartono
   in `ASF_ENV=test` e la pipeline scrive su `asf_test.db`.

4. In un altro terminale, verifica:

       ./scripts/asf-status.sh

   Atteso: `asf_test.db` ora esiste, `audit_trail` > 0 e agent_id `test-claude-code-agent`.
   `asf_local.db` (prod) resta invariato.

5. Nella dashboard premi il bottone **test**: vedi gli eventi appena generati.

## Procedura: tornare in produzione

Quando hai finito i test, chiudi la sessione test e riallinea l'ambiente:

       ./scripts/asf-prod.sh            # solo pulizia, poi avvii `claude` quando vuoi
       # oppure
       ./scripts/asf-prod.sh --launch   # pulisce e riapre subito claude in prod

La prossima sessione `claude` normale farà ripartire i daemon in produzione.

## Riepilogo: cosa avviare e quando

- Prima di una sessione di sviluppo/prova   ->  `./scripts/asf-test.sh`
- Per controllare dove sta scrivendo il sistema  ->  `./scripts/asf-status.sh`
- Finita la prova, per tornare operativo    ->  `./scripts/asf-prod.sh`
