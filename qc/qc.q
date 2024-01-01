// example usage 
// q qc.q -q :31337

if[not ":"=first .z.x 0;exit 1];

h:@[hopen; `$":",.z.x 0;{0}];

if[h=0;1"port does not exist..."; exit 1];

prompt:(.z.x 0),">";

evaluate:{.Q.s value x};

.z.pc:{if [h=x;exit 1]};

.z.pi:{if["\\\\\n"~x;value "\\\\"]; 1 @[{h(evaluate;x)};x;{"'",x,"\n"}];1 prompt};

1 prompt;