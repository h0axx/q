\P 17
\c 100 200

H:(0x6a09e667;0xbb67ae85;0x3c6ef372;0xa54ff53a;0x510e527f;0x9b05688c;0x1f83d9ab;0x5be0cd19);

K:(0x428a2f98;0x71374491;0xb5c0fbcf;0xe9b5dba5;0x3956c25b;0x59f111f1;0x923f82a4;0xab1c5ed5;
    0xd807aa98;0x12835b01;0x243185be;0x550c7dc3;0x72be5d74;0x80deb1fe;0x9bdc06a7;0xc19bf174;
    0xe49b69c1;0xefbe4786;0x0fc19dc6;0x240ca1cc;0x2de92c6f;0x4a7484aa;0x5cb0a9dc;0x76f988da;
    0x983e5152;0xa831c66d;0xb00327c8;0xbf597fc7;0xc6e00bf3;0xd5a79147;0x06ca6351;0x14292967;
    0x27b70a85;0x2e1b2138;0x4d2c6dfc;0x53380d13;0x650a7354;0x766a0abb;0x81c2c92e;0x92722c85;
    0xa2bfe8a1;0xa81a664b;0xc24b8b70;0xc76c51a3;0xd192e819;0xd6990624;0xf40e3585;0x106aa070;
    0x19a4c116;0x1e376c08;0x2748774c;0x34b0bcb5;0x391c0cb3;0x4ed8aa4a;0x5b9cca4f;0x682e6ff3;
    0x748f82ee;0x78a5636f;0x84c87814;0x8cc70208;0x90befffa;0xa4506ceb;0xbef9a3f7;0xc67178f2);

// Format hexbyte to binary
.sha256.hbtbin:{[x]
  raze {$[c:8-count binary:2 vs x;(c#0),binary;binary]} each x
  };

// Format binary to hexbyte
.sha256.binthb:{[x]
  if[not 0=type x;x:enlist x];
  raze {"x"${2 sv x} each 8 cut x} each x
  };

H:.sha256.hbtbin each H;
K:.sha256.hbtbin each K;

preprocess:{[x]
	// Map ASCII to INT, if we get a string value
	if[10=abs type x;x:`int$x];
	// Format to binary
	x:$[isSingle:count[x]=1;2 vs x;flip 2 vs x];
	// Make sure every row is 8-bit format
	x:$[isSingle;
	{$[r:8-count x;(r#0),x;x]} x;
	{$[r:8-count x;(r#0),x;x]} each x
	];
	// Make it single list
	x:raze x;
	// Get message count
	c:count x;
	// Append mandatory "1" padding
	x,:1;
	// Get message count with mandatory "1" padding and message length property
	c1:c+1+64;
	// Get final message length (including padding)
	c2:512*$[("j"$r)<r:c1%512;1+"j"$r;"j"$r];
	// Add message padding
	x,:$[0<padding:c2-c1;padding#0;()];
	// Get message length padding and message count in binary
	padding:64-count binC:2 vs c;
	// Add length property to message
	x:x,(padding#0),binC;
	// Distinguish blocks
	x:512 cut x;
	// Split message to 32-bits per row
	x:cut[32;] each x;
	schema:`${"M",string x} each til 16;
	{y!x}[;schema] each x
  };


// Sigma functions
sigma0:{ x:((-7#x),-7_x; (-18#x),-18_x;(3#0),-3_x); (sum each flip x) mod 2 };
sigma1:{ x:((-17#x),-17_x; (-19#x),-19_x;(10#0),-10_x); (sum each flip x) mod 2 };
Sigma0:{ x:((-2#x),-2_x;(-13#x),-13_x;(-22#x),-22_x); (sum each flip x) mod 2 };
Sigma1:{ x:((-6#x),-6_x;(-11#x),-11_x;(-25#x),-25_x); (sum each flip x) mod 2 };

// Choose function
Ch:{[e;f;g] ?["b"$e;f;g]};

// Majority function
Maj:{[a;b;c] x:sum each flip (a;b;c);?[x>1;1;0]};

// Addition Modulo 2^32
Mod232:{$[0<c:32-count r:2 vs sum {2 sv x} each x;(c#0),r;-32#r]};

// Initialize W
W:(til 64)!64#();

run:{
  {x set y}'[`$".sha256.",/: string `a`b`c`d`e`f`g`h;.sha256.H];
  W[til 16]:value x;
  {W[x]:Mod232 (sigma1[W[x-2]];W[x-7];sigma0[W[x-15]];W[x-16])} each 16+til 48;
  {
      T1:Mod232 (.sha256.h;Sigma1[.sha256.e];Ch[.sha256.e;.sha256.f;.sha256.g];K[x];W[x]);
      T2:Mod232 (Sigma0[.sha256.a];Maj[.sha256.a;.sha256.b;.sha256.c]);
      .sha256.h:.sha256.g;
      .sha256.g:.sha256.f;
      .sha256.f:.sha256.e;
      .sha256.e:Mod232 (.sha256.d;T1);
      .sha256.d:.sha256.c;
      .sha256.c:.sha256.b;
      .sha256.b:.sha256.a;
      .sha256.a:Mod232 (T1;T2);
	} each til 64;

  .sha256.H[0]:Mod232 (.sha256.a;.sha256.H[0]);
  .sha256.H[1]:Mod232 (.sha256.b;.sha256.H[1]);
  .sha256.H[2]:Mod232 (.sha256.c;.sha256.H[2]);
  .sha256.H[3]:Mod232 (.sha256.d;.sha256.H[3]);
  .sha256.H[4]:Mod232 (.sha256.e;.sha256.H[4]);
  .sha256.H[5]:Mod232 (.sha256.f;.sha256.H[5]);
  .sha256.H[6]:Mod232 (.sha256.g;.sha256.H[6]);
  .sha256.H[7]:Mod232 (.sha256.h;.sha256.H[7]);
  };

sha256:{[input]
  .sha256.H:H;
  x:preprocess input;
  run each x; 
  .sha256.binthb .sha256.H
  };