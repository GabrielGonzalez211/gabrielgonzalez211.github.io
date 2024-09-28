ctfCompetitionTemplate = '''---
layout: ctf_overview
title: {0}
category: {1}
date: {2}
---
'''

ctfWriteupTemplate = '''---
layout: writeup
category: {0}
description: {1}
points: {2}
solves: {3}
tags: {4}
date: {5}
title: {6}
comments: false
---

{{% raw %}}

{7}

{{% endraw %}}
'''
