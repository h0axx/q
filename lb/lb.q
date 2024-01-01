h:hopen each 1337 1338;
handles:h!count[h]#();
queue:()!();

.z.pg:{[query]
	queue[.z.w]:query;
	-30!(::)
	};

// Function to be called on resource
resourceFunc:{[clientHandle;query]
	neg[.z.w](`callback;clientHandle;@[(0b;);value@;query;{[error](1b;error)}])
	};

.z.ts:{
	if[not count queue;
		:()];
	if[not handle:0^first where () ~/: handles;
		:()];
	handles[handle]:(client:first key queue;query:first queue);
	queue _:client;
	neg[handle](resourceFunc;client;query);
	};

callback:{[clientHandle;result]
	handles[.z.w]:();
	-30!(clientHandle;result[0];result[1])
	};