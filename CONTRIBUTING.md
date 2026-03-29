# Contributing to mitnick

Thanks for your interest in contributing! This guide will help you get started.

## Reporting Bugs

Open an issue using the **Bug Report** template. Include:

- Steps to reproduce
- Expected vs actual behavior
- Node.js version, OS, and mitnick version
- Relevant error output

## Suggesting Features

Open an issue using the **Feature Request** template. Describe the problem you're trying to solve and your proposed solution.

## Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/mitnick.git
cd mitnick

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Type check
npm run typecheck

# Lint
npm run lint

# Run everything at once
npm run validate
```

## Code Style

- **TypeScript** with strict mode (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, etc.)
- **ESLint** with strict rules (no `any`, `strict-boolean-expressions`, `explicit-function-return-type`, etc.)
- **Prettier** for formatting (single quotes, trailing commas, 100 char width)
- **Husky + lint-staged** runs lint, typecheck, and all tests on every commit

The pre-commit hook ensures nothing broken gets committed. If it fails, fix the issues before committing.

## Adding a New Analyzer

1. Create a new directory under `src/analyzers/your-analyzer/`

2. Create `index.ts` implementing the `Analyzer` interface:

```typescript
import type { AnalysisContext, AnalyzerResult, Finding } from '../../core/types.js';
import type { Analyzer } from '../analyzer.interface.js';

export class YourAnalyzer implements Analyzer {
  readonly name = 'your-analyzer';
  readonly description = 'What this analyzer detects';

  analyze(context: AnalysisContext): Promise<AnalyzerResult> {
    const start = performance.now();
    const findings: Finding[] = [];

    // Your analysis logic here

    return Promise.resolve({
      analyzer: this.name,
      findings,
      duration: performance.now() - start,
    });
  }
}
```

If your analyzer walks files, extend `FileBasedAnalyzer` instead:

```typescript
import { FileBasedAnalyzer } from '../file-based-analyzer.js';

export class YourAnalyzer extends FileBasedAnalyzer {
  readonly name = 'your-analyzer';
  readonly description = 'What this analyzer detects';

  protected analyzeFile(source: string, relativePath: string): Finding[] {
    // Analyze a single file, return findings
    return [];
  }
}
```

3. Register it in `src/analyzers/analyzer.registry.ts`

4. Write tests in `tests/unit/analyzers/your-analyzer.test.ts`

5. Update the README analyzer table

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org):

```
feat: add new dependency-age analyzer
fix: handle scoped packages in typosquatting check
docs: update README with new CLI flags
refactor: extract shared entropy calculation
test: add edge cases for obfuscation detector
chore: update typescript to 5.7
```

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `npm run validate` passes (typecheck + lint + tests)
4. Write or update tests for your changes
5. Update documentation if needed
6. Open a PR using the pull request template
7. Wait for review

## Testing

- All tests must pass before merging
- New features require tests
- New analyzers require comprehensive unit tests with fixture data
- Target: 80% code coverage
- Use `npm run test:coverage` to check coverage

## Code Review

All PRs require at least one review from a maintainer. Reviews focus on:

- Correctness and security
- Test coverage
- TypeScript type safety
- Consistency with existing patterns
