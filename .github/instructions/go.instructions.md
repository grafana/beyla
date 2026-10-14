---
applyTo: "**/*.go"
---

# Go Code Instructions

When working on Go code in this repository, follow these rules strictly.

Prioritize clarity, simplicity, and consistency with existing code over abstraction or cleverness.

General rules:

- Prefer simple, explicit logic over clever or compact code.
- Keep functions small and focused. Split large functions when needed.
- Prefer early returns when they improve readability and reduce indentation depth.
- Use vertical spacing to separate logical blocks when it improves readability.
- Do not use magic numbers. Name constants or derive values from existing types and objects.
- Reuse existing utilities, helpers, and patterns instead of introducing duplicate implementations.
- Avoid unnecessary allocations, unnecessary conversions, and unnecessary `unsafe` usage.
- Follow existing naming, structure, and patterns in the surrounding code.

Comments:

- Do not add comments that restate the code.
- Prefer clearer code over explanatory comments.
- Add comments only when they provide necessary context or explain non-obvious behavior.

Abstractions:

- Avoid unnecessary interfaces. Do not introduce interfaces unless required by an existing design boundary, multiple implementations, or tests.
- Avoid over-abstraction. Prefer concrete types and straightforward code.
- Do not introduce new layers, wrappers, or indirection without a clear need.
- Do not introduce speculative abstractions.

Structure:

- Respect existing package boundaries and responsibilities.
- Do not move code across packages without a clear reason.
- If avoiding duplication requires a small, relevant refactor to reuse an existing implementation, prefer that over adding a parallel code path.
- Keep changes scoped to the relevant subsystem.

Validation:

- Ensure changes compile and pass existing tests.
- Do not introduce changes that break linting or formatting rules.

When reviewing Go changes, flag unnecessary abstractions, duplicated logic, awkward mechanical conditionals, violations of existing patterns, branch-heavy code without targeted tests, and changes that increase complexity without clear benefit.
