# Contributing to Skidrow Killer

Thank you for your interest in contributing to Skidrow Killer! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please:

- Be respectful and considerate in all interactions
- Focus on constructive feedback
- Accept and provide constructive criticism gracefully
- Prioritize what's best for the community and security

## Getting Started

### Prerequisites

- Windows 10/11 (64-bit)
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)
- Git

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Skidrowkiller.git
   cd Skidrowkiller
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/xjanova/Skidrowkiller.git
   ```

## Development Setup

### Build the Project

```bash
# Restore dependencies
dotnet restore

# Build in Debug mode
dotnet build -c Debug

# Build in Release mode
dotnet build -c Release
```

### Run the Application

```bash
# Run in Debug mode (requires Administrator)
dotnet run
```

**Note:** The application requires Administrator privileges for full functionality.

### Build Portable Version

```bash
# Using build script
.\build-portable.bat

# Or manually
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

## Making Changes

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `security/description` - Security improvements

### Workflow

1. Sync with upstream:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. Make your changes and commit:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

4. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

5. Open a Pull Request

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Maintenance tasks
- `security`: Security improvements

Examples:
```
feat(scanner): add YARA rule support
fix(monitor): resolve memory leak in real-time monitoring
docs: update installation instructions
security: improve signature validation
```

## Pull Request Process

1. **Update Documentation**: If your change affects usage, update the README or relevant docs

2. **Add Tests**: If applicable, add or update tests for your changes

3. **Follow Code Style**: Ensure your code follows the project's coding standards

4. **One Feature Per PR**: Keep pull requests focused on a single feature or fix

5. **Describe Your Changes**: Provide a clear description in the PR:
   - What changes were made
   - Why the changes were necessary
   - How to test the changes

6. **Review Process**:
   - Address all review comments
   - Keep the PR updated with the main branch
   - Squash commits if requested

## Coding Standards

### C# Style Guide

- Use `var` when type is obvious
- Use file-scoped namespaces
- Private fields should start with `_` (underscore)
- Async methods should end with `Async`
- Use meaningful names for variables and methods
- Keep methods focused and concise

### XAML Style Guide

- Use 2-space indentation
- Group related properties together
- Use StaticResource for reusable styles
- Keep complex logic in code-behind or ViewModels

### Security Guidelines

Since this is a security tool, please:

- Never commit sensitive data or credentials
- Validate all user inputs
- Handle exceptions gracefully without exposing internals
- Use secure coding practices
- Document any security implications of changes

## Testing

### Running Tests

```bash
# Run all tests
dotnet test

# Run with coverage
dotnet test /p:CollectCoverage=true
```

### Manual Testing Checklist

Before submitting a PR, test:

- [ ] Application starts correctly (as Administrator)
- [ ] File scanning works
- [ ] Registry scanning works
- [ ] Process scanning works
- [ ] Real-time monitoring works
- [ ] Signature updates work
- [ ] UI is responsive during operations
- [ ] Pause/Resume/Stop functions work
- [ ] Logs are generated correctly

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **Environment Info**:
   - Windows version
   - .NET version
   - Skidrow Killer version

2. **Steps to Reproduce**:
   - Clear, numbered steps
   - Expected vs actual behavior

3. **Logs**:
   - Relevant log files from `Documents\SkidrowKiller\Logs\`

4. **Screenshots**:
   - If applicable, include screenshots

### Feature Requests

For feature requests:

1. Check if the feature already exists or is planned
2. Describe the use case and benefit
3. Provide examples if possible

### Security Issues

**For security vulnerabilities, please do NOT create a public issue.**

Instead, contact the maintainers directly or use GitHub's private vulnerability reporting feature.

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Read the documentation in `/docs`
3. Open a discussion on GitHub

---

Thank you for contributing to making Windows systems safer!
