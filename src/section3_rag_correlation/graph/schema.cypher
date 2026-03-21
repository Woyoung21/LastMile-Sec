// Neo4j 5.13+ — vector indexes (768 dimensions for gemini-embedding-001 output_dimensionality).
// Run via apply_schema() in neo4j_client.py (idempotent).

CREATE CONSTRAINT vendor_name_unique IF NOT EXISTS
FOR (v:Vendor) REQUIRE v.name IS UNIQUE;

CREATE CONSTRAINT control_id_unique IF NOT EXISTS
FOR (c:Control) REQUIRE c.control_id IS UNIQUE;

CREATE CONSTRAINT mitre_technique_unique IF NOT EXISTS
FOR (m:Mitre) REQUIRE m.technique_id IS UNIQUE;

CREATE VECTOR INDEX control_remediation_vector IF NOT EXISTS
FOR (c:Control) ON (c.remediation_embedding)
OPTIONS { indexConfig: {
  `vector.dimensions`: 768,
  `vector.similarity_function`: 'cosine'
}};
