encodeMap:til[64]!.Q.b6;
decodeMap:.Q.b6!til 64;


// encoding
encode:{[x]
	binary:flip 2 vs `int$x;
	binary:{$[0<c:8-count x;(c#0),x;x]} each binary;
	binary:6 cut raze binary;
	if[not 0=c:6-count last binary;binary:(-1_binary),enlist (last[binary],c#0)];
	encoded:encodeMap 2 sv flip binary;
	if[not 4=c:4-count[encoded] mod 4;encoded,:c#"="];
	encoded
	};

// decoding
decode:{[x]
	encoded:x except "=";
	binary:flip 2 vs decodeMap[encoded];
	binary:{$[0<c:6-count x;(c#0),x;x]} each binary;
	binary:8 cut raze binary;
	if[not 8=count last binary;binary:-1_binary];
	decoded:"c"$2 sv flip binary;
	decoded
	};
