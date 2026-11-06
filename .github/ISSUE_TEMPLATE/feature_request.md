---
name: Feature request
about: Suggest a new tool, parameter, or server capability for this fork
title: "[feature] "
labels:
  - enhancement
---

**What kind of feature?**
- [ ] Expose an FFDec CLI command that has no dedicated tool yet
- [ ] New parameter/option on an existing tool
- [ ] Server behavior (FFDec detection/download, timeouts, logging, output shape)
- [ ] Documentation
- [ ] Other (please describe)

**Is your feature request related to a problem? Please describe.**
A clear and concise description of the problem or workflow, e.g. "I'm trying to
edit X in a SWF and there is no tool for it".

**Describe the solution you'd like**
For a new tool: which FFDec CLI command should be wrapped (see
https://github.com/jindrapetrik/jpexs-decompiler/wiki/Commandline-arguments),
a proposed snake_case tool name, and its parameters.
For anything else: a clear description of what should happen.

**Why a dedicated tool?**
A generic `run_ffdec` passthrough already executes any FFDec command. Please
explain what a dedicated tool would add — e.g. input validation, structured
results, schema-documented parameters, output verification.

**Describe alternatives you've considered**
Other approaches, existing tools that partially cover it, or upstream projects:
- FFDec itself: https://github.com/jindrapetrik/jpexs-decompiler
- Base wrapper: https://github.com/sublimnl/ffdecmcp
A PR upstream may be the better home for changes that are not fork-specific.

**Environment (optional):**
- ffdecmcp-ext version: [e.g. 0.2.1]
- OS / Python / Java / FFDec version: [if relevant]

**Additional context**
Any other context, mockups, or example SWF workflows.
