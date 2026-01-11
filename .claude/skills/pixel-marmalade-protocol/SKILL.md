---
name: pixel-marmalade-protocol
description: Architecture framework for building scalable, future-proof Flutter applications. Use when starting any new Flutter project, making architectural decisions, or setting up project structure. Covers foundation-first development, dynamic content delivery, privacy-first design, modular architecture.
---

# Pixel Marmalade Protocol

## Six Core Principles

### 1. Modern Foundation
Build scalable, dynamic systems that bypass App Store update delays.
- Use Shorebird for instant code push updates
- Server-Driven UI (SDUI) for content changes without app updates
- JSON-based content loading for dynamic data

### 2. MVP-First
Build the smallest usable thing, then iterate.
- Define absolute minimum feature set before coding
- Ship working software early and often
- No gold-plating until foundation is validated

### 3. Claude Code + Deep Research
Load Claude with domain research before building.
- Gather domain-specific research topics before development
- Organize research in `/research/` folder structure
- Use Marine Corps Protocol for scope control

### 4. Privacy-First
Local processing, anonymous telemetry only, zero liability.
- Process sensitive data on-device, never server-side
- Anonymous analytics only (no PII collection)
- User controls for all data sharing

### 5. Secure File Handling
Sandboxed imports, sanitized exports.
- All file imports go through validation
- Sanitize all exported data
- Platform-appropriate sandboxing

### 6. Build and Ship
Make the dream reality.
- Bias toward action over planning
- Done is better than perfect
- Customer value is the only metric

## Project Structure

```
lib/
├── main.dart
├── app/
│   ├── app.dart
│   ├── router.dart
│   └── theme/
├── core/
│   ├── constants/
│   ├── utils/
│   └── errors/
├── data/
│   ├── models/
│   ├── repositories/
│   └── datasources/
├── domain/
│   ├── entities/
│   ├── repositories/
│   └── usecases/
├── features/
│   └── feature_name/
│       ├── presentation/
│       ├── domain/
│       └── data/
└── shared/
    ├── widgets/
    ├── services/
    └── providers/
```

## Architecture Rules

1. **Features are self-contained**: Each feature has own presentation, domain, data
2. **Core never imports features**: Core utilities are shared
3. **Shared widgets are generic**: No business logic in shared widgets
4. **Data flows one direction**: UI → Controllers → UseCases → Repositories
