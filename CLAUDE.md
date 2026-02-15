# Velka Project Rules (Token-Saver Mode)

## Concision & Economy
- **UltraCompressed Output:** Nunca use preâmbulos ("Sure", "I'll help"). Vá direto ao código ou plano.
- **Diff-Only:** Em implementações, forneça apenas o diff ou as linhas alteradas, nunca o arquivo completo.
- **Skip Explanation:** Não explique conceitos básicos de Rust (Ownership, Traits). Assuma nível Sênior.

## Workflow de Análise (Plan Mode)
1. **Exploração:** Antes de propor, use `grep` ou `ls` para entender a estrutura de `src/domain` e `src/engine`.
2. **PLAN.md:** Escreva sempre um arquivo `PLAN.md` com a estratégia antes de alterar o código.
3. **Context Reset:** Após eu aprovar o plano, eu executarei `/clear` e você lerá o `PLAN.md` para implementar. Isso evita carregar o histórico da discussão de planejamento para a fase de escrita.

## Tech Stack Constraints (Velka)
- **Performance:** Priorize `memmap2` e processamento paralelo (estratégia já presente em `src/main.rs`).
- **Zero Telemetry:** Mantenha a promessa do README de privacidade absoluta.