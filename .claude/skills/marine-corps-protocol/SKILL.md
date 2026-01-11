---
name: marine-corps-protocol
description: Meta-framework for deploying Claude Code instances with military precision. Use when starting any new development task, establishing scope boundaries, or managing multi-phase projects. Defines mission briefing structure, security clearance levels, rules of engagement, and phase-gate methodology.
---

# Marine Corps Protocol

## Overview

This protocol governs how Claude Code instances are deployed on missions. Every task is a mission with defined objectives, boundaries, and rules of engagement. This prevents scope creep, context pollution, and ensures focused execution.

## Core Principles

1. **Narrow Security Clearance**: Each Claude instance knows only what it needs for its specific mission
2. **Mission-Specific Briefing**: Load only relevant context, research, and skills
3. **Defined Boundaries**: Explicit list of what's in-scope and out-of-scope
4. **Phase Gates**: Checkpoint before advancing to prevent compounding errors
5. **Clean Extraction**: Mission ends with deliverables, not open threads

## Mission Briefing Template

Every mission begins with a structured briefing:

```markdown
## MISSION: [Codename]
**Objective**: [Single sentence describing success state]
**Security Clearance**: [What this instance is allowed to know/modify]

### Context Load
- [Relevant skill files to read]
- [Research documents to reference]
- [Existing code to understand]

### Rules of Engagement
- DO: [Explicit list of allowed actions]
- DO NOT: [Explicit list of forbidden actions]
- ASK BEFORE: [Actions requiring confirmation]

### Success Criteria
- [ ] [Measurable outcome 1]
- [ ] [Measurable outcome 2]
- [ ] [Measurable outcome 3]

### Extraction Protocol
[What to deliver when mission complete]
```

## Security Clearance Levels

### Level 1: Reconnaissance
- Read-only access
- Can analyze, report, recommend
- Cannot modify any files
- Use for: Code review, research, planning

### Level 2: Tactical
- Can modify files within specified directory
- Cannot create new architectural patterns
- Cannot modify core systems
- Use for: Bug fixes, feature additions to existing systems

### Level 3: Strategic
- Can create new files and directories
- Can establish new patterns
- Cannot modify existing core architecture
- Use for: New feature development, new modules

### Level 4: Command
- Full access to codebase
- Can refactor core systems
- Can modify architecture
- Use for: Major refactors, architecture changes
- **Requires**: Explicit human approval at each phase gate

## Phase Gate Methodology

### Phase 1: Reconnaissance
- Understand current state
- Identify all affected systems
- Map dependencies
- **Gate**: Present findings, get approval to proceed

### Phase 2: Planning
- Design solution
- Identify risks
- Create rollback plan
- **Gate**: Present plan, get approval to proceed

### Phase 3: Execution
- Implement solution
- Follow established patterns
- Document changes
- **Gate**: Present implementation, get approval for testing

### Phase 4: Verification
- Test implementation
- Verify no regressions
- Confirm success criteria met
- **Gate**: Present results, get approval for extraction

### Phase 5: Extraction
- Clean up temporary files
- Update documentation
- Hand off deliverables
- **Complete**: Mission ends

## Rules of Engagement

### Always
- State assumptions before acting on them
- Ask clarifying questions if mission parameters are ambiguous
- Report blockers immediately
- Maintain focus on stated objective

### Never
- Expand scope without explicit approval
- Modify files outside security clearance
- Make "improvements" not requested in mission
- Leave work in incomplete state at extraction

### Ask Before
- Creating new architectural patterns
- Modifying shared utilities
- Adding new dependencies
- Deviating from established conventions

## Anti-Patterns

### Scope Creep
❌ "While I'm here, I'll also refactor this..."
✅ "I noticed X could be improved. Should I create a separate mission for that?"

### Context Pollution
❌ Loading entire codebase for a bug fix
✅ Loading only the module containing the bug

### Incomplete Extraction
❌ "Here's what I started, you can finish..."
✅ "Mission complete. Here are the deliverables: ..."

### Assumption Cascade
❌ Making a chain of assumptions without verification
✅ "I'm assuming X because Y. Should I proceed on this basis?"

## Mission Log Template

After each mission, log:

```markdown
## Mission: [Codename]
**Status**: Complete | Aborted | Handed Off
**Duration**: [Time spent]

### Completed
- [What was accomplished]

### Discoveries
- [Unexpected findings]

### Technical Debt Created
- [Any shortcuts taken]

### Recommended Follow-up Missions
- [Future work identified]
```
