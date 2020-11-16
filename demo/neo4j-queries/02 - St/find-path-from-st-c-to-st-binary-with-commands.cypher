// Find path from "st.c" to st binary (with commands)
MATCH (src:File {basename: "st.c"})
MATCH (dst:File {basename: "st"})
CALL apoc.path.expandConfig(src, {
	sequence: "File,<READS,Process,WRITES>",
    minLevel: 1,
    maxLevel: 6,
    uniqueness: "NODE_GLOBAL",
    endNodes: [dst]
})
YIELD path
MATCH (p:Process)-[:EXECS]->(f:File) WHERE any(n in nodes(path) where p=n)
RETURN path, f
LIMIT 100