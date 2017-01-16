---
layout: post
title: Facebook Hacker Cup 2017 QR
---

한 문제 이상만 풀면 진출할 수 있었기 때문에 가벼운 마음으로 참가했다.

### 25: [Progress Pie](https://www.facebook.com/hackercup/problem/1254819954559001/)

0에서 시작해 100까지 올라가는 progress pie가 있고, 중심이 (50, 50)이고 반지름 이 50일 때 주어진 점이 특정 progress에서 pie 안에 속하는지를 구하면 된다. 점이 pie의 경계 위에 주어지는 일도 없으므로 pie의 중심으로부터 50 이내에 있을 때 현재 progress와 비교하면 간단히 구할 수 있다.

나는 `math.atan2()`를 사용했는데, 문제의 progress pie는 y축에서 시계방향으로 진행하지만 `atan2()`는 x축에서 반시계방향으로 진행한다는 점을 고려하지 않는 어처구니없는 실수를 저질러 가장 쉬운 문제를 득점하지 못했다.

```python
from math import atan2, pi

for tc in range(int(input())):
    p, x, y = map(int, input().split())
    x -= 50
    y -= 50
    color = 'white'
    if x ** 2 + y ** 2 <= 50 ** 2:
        r = atan2(y, x) / pi * 50
        r = 25 - r
        if r < 0:
            r += 100
        if r < p:
            color = 'black'
    print('Case #{}: {}'.format(tc + 1, color))
```

### 30: [Lazy Loading](https://www.facebook.com/hackercup/problem/169401886867367/)

제목이 눈에 띈다.

$$N$$개의 짐이 있을 때 각 가방이 최소 50파운드의 무게를 가져 보이도록 최대한 많은 가방으로 짐을 분배하는 것이 문제가 요구하는 조건이다. 각 가방에 들어있는 짐은 그 가방에서 가장 무거운 짐의 무게로 보이(게 할 수 있으)므로 무거운 짐들을 최대한 많은 가방으로 분산시켜 묻어가는 가벼운 짐을 많이 확보하도록 greedy하게 풀면 된다.

구체적으로는 짐을 무게에 따라 정렬한 뒤 무거운 짐을 하나씩 새로운 가방에 할당하면서 가방이 50파운드 이상의 무게로 보이도록 가벼운 짐을 추가하면 된다. 남는 짐은 어떻게든 새로운 가방을 만들 수 없으므로 가방의 개수에는 영향을 미치지 않기 떄문에 무시한다.

시간복잡도는 $$O(N)$$ 이지만 제한이 넉넉해 적당히 구현했다.

```python
for tc in range(int(input())):
    n = int(input())
    m = [int(input()) for _ in range(n)]
    m.sort()
    c = 0
    while m:
        l = m.pop()
        d = int((50 - 1) / l)
        if d <= len(m):
            c += 1
        m = m[d:]
    print('Case #{}: {}'.format(tc + 1, c))
```
