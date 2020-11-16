// hello.c compilation
MATCH (p:Process) -[:READS]-> (f:File{basename: "hello.c"})
RETURN *
LIMIT 1