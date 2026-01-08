## snow隐写
```
>python snow.py -C -p 123456 -m "flag{aaa}" test.txt testa.txt
Compressed by 18.06%
Message used approximately 22.78% of available space.
>python snow.py -C -p 123456 testa.txt
flag{aaa}
>python snow.py -C -m "flag{bbb}" test.txt testa.txt
Compressed by 9.72%
Message used approximately 24.53% of available space.
>python snow.py -C testa.txt
flag{bbb}
>python snow.py -m "flag{ccc}" test.txt testc.txt
Message used approximately 26.57% of available space.
>python snow.py testc.txt
flag{ccc}
```
