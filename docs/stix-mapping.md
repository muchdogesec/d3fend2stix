Objects are generated from The D3FEND Ontology distribution in JSON-LD Graph format.

You can find it here: https://d3fend.mitre.org/resources/ontology/

## STIX Objects

### Default objects

Added to all bundles

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/d3fend2stix.json


### Matrix

```json
{
  "type": "x-mitre-matrix",
  "id": "x-mitre-matrix--<UUID v5>",
  "created": "<d3f:release-date>",
  "modified": "<d3f:release-date>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "name": "D3fend",
  "description": "A knowledge graph of cybersecurity countermeasures",
  "tactic_refs": [
    "ALL_TACTICS"
  ],
  "external_references": [
    {
      "source_name": "mitre-d3fend",
      "url": "https://d3fend.mitre.org/",
      "external_id": "mitre-d3fend"
    }
  ],
  "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
  ]
    
}
```

UUID namespace `6923e7d4-e142-508c-aefc-b5f4dd27dc22` and value is `mitre-d3fend`

### Tactics

Identified where `@type` is `d3f:DefensiveTactic`

```json
    {
      "@id": "d3f:Detect",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:DefensiveTactic"
      ],
      "d3f:definition": "The detect tactic is used to identify adversary access to or unauthorized activity on computer networks.",
      "d3f:display-order": 1,
      "d3f:display-priority": 0,
      "rdfs:label": "Detect",
      "rdfs:subClassOf": {
        "@id": "d3f:DefensiveTactic"
      }
    },
```

```json
{
	"type": "x-mitre-tactic",
	"id": "x-mitre-tactic--<UUID v5>",
	"created": "<d3f:release-date>",
	"modified": "<d3f:release-date>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"name": "<rdfs:label>",
	"description": "<d3f:definition>",
  "x_mitre_shortname": "lowercase <rdfs:label>",
	"external_references": [
		{
	    	"source_name": "mitre-d3fend",
	    	"url": "https://d3fend.mitre.org/tactic/<@id>",
	    	"external_id": "@id"
	    }
	],
	"object_marking_refs": [
    	"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    	"marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
	]
}
```

UUID namespace `6923e7d4-e142-508c-aefc-b5f4dd27dc22` and value is `@id`

#### Technique (level 0: general)

Identified where `rdfs:subClassOf.@id` is `d3f:DefensiveTechnique`

```json
    {
      "@id": "d3f:FileAnalysis",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:FileAnalysis"
      ],
      "d3f:analyzes": {
        "@id": "d3f:File"
      },
      "d3f:d3fend-id": "D3-FA",
      "d3f:definition": "File Analysis is an analytic process to determine a file's status. For example: virus, trojan, benign, malicious, trusted, unauthorized, sensitive, etc.",
      "d3f:enables": {
        "@id": "d3f:Detect"
      },
      "d3f:kb-article": "## Technique Overview\nSome techniques use file signatures or file metadata to compare against historical collections of malware. Files may also be compared against a source of ground truth such as cryptographic signatures. Examining files for potential malware using pattern matching against file contents/file behavior. Binary code may be dissembled and analyzed for predictive malware behavior, such as API call signatures. Analysis might occur within a protected environment such as a sandbox or live system.",
      "rdfs:label": "File Analysis",
      "rdfs:subClassOf": [
        {
          "@id": "d3f:DefensiveTechnique"
        },
        {
          "@id": "_:N939454cd94094260ba4351ace5cffa90"
        },
        {
          "@id": "_:N1b3e3e7b4d5c422ba0fa7907c964949e"
        }
      ]
    },
```

```json
{
	"type": "course-of-action",
	"id": "course-of-action--<UUID v5>",
	"created": "<d3f:release-date>",
	"modified": "<d3f:release-date>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"name": "<rdfs:label>",
	"description": "<d3f:definition>\n<d3f:kb-article>",
	"x_aliases": [
		"<d3f:synonyms>"
	],
  "x_mitre_domains": [
    "d3fend"
  ],
  "x_mitre_is_subtechnique": "<if subclass of tactic is false, else true>",
	"external_references": [
		{
	    	"source_name": "mitre-d3fend",
	    	"url": "https://d3fend.mitre.org/technique/<@id>",
	    	"external_id": "<d3f:d3fend-id>"
	  },
    {
        "source_name": "mitre-d3fend",
        "description": "This technique enables the tactic <TACTIC NAME>",
        "url": "https://d3fend.mitre.org/tactic/d3f:<TACTIC ID>",
        "external_id": "<TACTIC ID>"
    },
		{
	    	"source_name": "<seeAlso>",
        "description": "<seeAlso>",
	    	"url": "<seeAlso>"
	  },
    {
        "source_name": "<seeAlso>",
        "description": "<seeAlso>",
        "url": "<seeAlso>"
    },
    {
        "source_name": "d3f:kb-reference.rdfs:label",
        "descripiton": "d3f:kb-reference.d3f:kb-abstract",
        "url": "d3f:kb-reference.has-link.@value",
    },
    {
        "source_name": "d3f:kb-reference.rdfs:label",
        "descripiton": "d3f:kb-reference.d3f:kb-abstract",
        "url": "d3f:kb-reference.has-link.@value",
    }
	],
	"object_marking_refs": [
    	"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    	"marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
	]
}
```

UUID namespace `6923e7d4-e142-508c-aefc-b5f4dd27dc22` and value is `@id`


#### A note on kb references

```json
    {
      "@id": "d3f:Reference-MalwareAnalysisSystem_PaloAltoNetworksInc",
      "@type": [
        "owl:NamedIndividual",
        "d3f:PatentReference"
      ],
      "d3f:has-link": {
        "@type": "xsd:anyURI",
        "@value": "https://patents.google.com/patent/US20150319136A1"
      },
      "d3f:kb-abstract": "In some embodiments, a malware analysis system includes receiving a potential malware sample from a firewall; analyzing the potential malware sample using a virtual machine to determine if the potential malware sample is malware; and automatically generating a signature if the potential malware sample is determined to be malware. In some embodiments, the potential malware sample does not match a preexisting signature, and the malware is a zero-day attack.",
      "d3f:kb-author": "Huagang Xie; Xinran Wang; Jiangxia Liu",
      "d3f:kb-mitre-analysis": "This patent describes a VM sandbox environment that uses heuristic based analysis techniques performed in real-time during a file transfer to determine if the file is malicious. A new signature can then be generated and distributed to automatically block future file transfer requests to download the malicious file.",
      "d3f:kb-organization": "Palo Alto Networks Inc",
      "d3f:kb-reference-of": {
        "@id": "d3f:DynamicAnalysis"
      },
      "d3f:kb-reference-title": "Malware analysis system",
      "rdfs:label": "Reference - Malware analysis system - Palo Alto Networks Inc"
    },
```

#### Relationships

```json
      "rdfs:subClassOf": [
        {
          "@id": "d3f:DefensiveTechnique"
        },
        {
          "@id": "_:N939454cd94094260ba4351ace5cffa90"
        },
        {
          "@id": "_:N1b3e3e7b4d5c422ba0fa7907c964949e"
        }
      ]
    },
```


`rdfs:subClassOf` of techniques can contain references to other objects;

```json
    {
      "@id": "_:N939454cd94094260ba4351ace5cffa90",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:analyzes"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:File"
      }
    },
    {
      "@id": "_:N1b3e3e7b4d5c422ba0fa7907c964949e",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:enables"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:Detect"
      }
    },
```

Here the link to a tactic (`d3f:Detect`) and artifact (`d3f:File`) is shown both are indirect.

Note, there is also a direct link from this object `d3f:DefensiveTechnique`. `d3f:DefensiveTechnique` should always be ignored.

Here, 2 sros would be created, to d3f:File and to d3f:Detect

Relationships are created like so;

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<source.created>",
  "modified": "<target.created>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "<d3fend OR modified relationship-type>",
  "source_ref": "<source.id>",
  "target_ref": "<target.id>",
  "description": "<source.name> <d3fend relationship-type> <target.name>",
  "external_references": [
    {
        "source_name": "mitre-d3fend",
        "url": "https://d3fend.mitre.org/technique/<source.@id>",
        "external_id": "<d3f:d3fend-id>"
    },
    {
        "source_name": "mitre-d3fend",
        "url": "https://d3fend.mitre.org/technique/<target.@id>",
        "external_id": "<d3f:d3fend-id>"
    }
    {
        "source_name": "mitre-d3fend",
        "description": "relationship-type",
        "external_id": "<d3fend relationship-type>"
    },
  ],
  "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
  ]
```

UUID namespace `6923e7d4-e142-508c-aefc-b5f4dd27dc22` and value is `<source_ref>+<target_ref>+<relationship_type>`

#### Relationship types

To support the ATT&CK navigator, we need to include some standard relationships. This only applies to Sub-techniques -> Techniques, and Sub-techniques -> Sub-techniques. If not one of these joins, then the `relationship_type` in all places matches that from the d3fend file. Note, we do not need to include a relationship-type external_reference section for these objects.

However if Sub-techniques -> Techniques, or Sub-techniques -> Sub-techniques we need to us the `relationship_type` = `subtechnique-of`. To ensure we don't lose the original definition, we should track the original relationship type in the description AND in external_references.

We also link Sub-(Sub)-Techniques back to the Tactic using an enables type relationship.

### Relationship targets to artifacts

In the case of artifacts e.g. for `d3f:File` (not tactics/techniques, e.g. `d3f:Detect`).

These artifact objects need to be created on the fly

Here is an example of artifact `d3f:CertificateFile`

```json
    {
      "@id": "d3f:CertificateFile",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual"
      ],
      "d3f:contains": {
        "@id": "d3f:Certificate"
      },
      "d3f:definition": "A file containing a digital certificate. In cryptography, a public key certificate (also known as a digital certificate or identity certificate) is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.",
      "rdfs:isDefinedBy": {
        "@id": "dbr:Public_key_certificate"
      },
      "rdfs:label": "Certificate File",
      "rdfs:subClassOf": [
        {
          "@id": "d3f:File"
        },
        {
          "@id": "_:Nd26d70fae05b4a5899554c863b85a132"
        }
      ]
    },
```

We Indicators to represent these (we need to hack the pattern a bit)

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "<d3f:release-date>",
  "modified": "<d3f:release-date>",
  "indicator_types": ["unknown"],
  "name": "<rdfs:label>",
  "description": "<d3f:definition>",
  "pattern": "<@id>",
  "pattern_type": "d3fend",
  "valid_from": "<created>",
  "external_references": [
    {
        "source_name": "mitre-d3fend",
        "url": "https://d3fend.mitre.org/dao/artifact/<@id>",
        "external_id": "@id"
      }
  ],
  "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
  ]
}
```

UUID namespace `6923e7d4-e142-508c-aefc-b5f4dd27dc22` and value is `@id`

Note artifacts also contain subclasses. We need to create Indicators and SROs for these

```json
      "rdfs:subClassOf": [
        {
          "@id": "d3f:File"
        },
        {
          "@id": "_:Nd26d70fae05b4a5899554c863b85a132"
        }
```

```json
    {
      "@id": "_:Nd26d70fae05b4a5899554c863b85a132",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:contains"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:Certificate"
      }
    },
```

`d3f:File` is direct, `d3f:Certificate` is indirect

#### Technique (level 1: specific)

```json
    {
      "@id": "d3f:DynamicAnalysis",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:DynamicAnalysis"
      ],
      "d3f:analyzes": [
        {
          "@id": "d3f:DocumentFile"
        },
        {
          "@id": "d3f:ExecutableFile"
        }
      ],
      "d3f:d3fend-id": "D3-DA",
      "d3f:definition": "Executing or opening a file in a synthetic \"sandbox\" environment to determine if the file is a malicious program or if the file exploits another program such as a document reader.",
      "d3f:kb-article": "## How it works\nAnalyzing the interaction of a piece of code with a system while the code is being executed in a controlled environment such as a sandbox, virtual machine, or simulator. This exposes the natural behavior of the piece of code without requiring the code to be disassembled.\n\n## Considerations\n * Malware often detects a fake environment, then changes its behavior accordingly. For example, it could detect that the system clock is being sped up in an effort to get it to execute commands that it would normally only execute at a later time, or that the hardware manufacturer of the machine is a virtualization provider.\n * Malware can attempt to determine if it is being debugged, and change its behavior accordingly.\n * For maximum fidelity, the simulated and real environments should be as similar as possible because the malware could perform differently in different environments.\n * Sometimes the malware behavior is triggered only under certain conditions (on a specific system date, after a certain time, or after it is sent a specific command) and can't be detected through a short execution in a virtual environment.\n\n## Implementations\n* Cuckoo Sandbox",
      "d3f:kb-reference": [
        {
          "@id": "d3f:Reference-MalwareAnalysisSystem_PaloAltoNetworksInc"
        },
        {
          "@id": "d3f:Reference-UseOfAnApplicationControllerToMonitorAndControlSoftwareFileAndApplicationEnvironments_SophosLtd"
        }
      ],
      "d3f:synonym": [
        "Malware Detonation",
        "Malware Sandbox"
      ],
      "rdfs:label": "Dynamic Analysis",
      "rdfs:subClassOf": [
        {
          "@id": "d3f:FileAnalysis"
        },
        {
          "@id": "_:N12b4b8fab83840f38611dbeb38c709d8"
        },
        {
          "@id": "_:N914b12e4e18f481e99079a31c382ea11"
        }
      ]
```

```json
    {
      "@id": "_:N12b4b8fab83840f38611dbeb38c709d8",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:analyzes"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:DocumentFile"
      }
    },
    {
      "@id": "_:N914b12e4e18f481e99079a31c382ea11",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:analyzes"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:ExecutableFile"
      }
    },
```

Here, 3 sros would be created, to d3f:FileAnalysis, d3f:DocumentFile, d3f:ExecutableFile

Mapped in same way a level 0.

Note, see here `"d3f:FileAnalysis"` is a direct link and the object does exist (so a relationship will be created)

#### Technique (level 1: specific)

```json
    {
      "@id": "d3f:FileContentAnalysis",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:FileContentAnalysis"
      ],
      "d3f:d3fend-id": "D3-FCOA",
      "d3f:definition": "Employing a pattern matching algorithm to statically analyze the content of files.",
      "d3f:kb-article": "## How it works\nAnalyzing a piece of code without it being executed in a sandbox, virtual machine, or simulator. Patterns or signatures in the file can indicate whati kind of software it is, including whether it is malware.",
      "d3f:kb-reference": {
        "@id": "d3f:Reference-CyberVaccineAndPredictiveMalwareDefensiveMethodsAndSystems"
      },
      "rdfs:label": "File Content Analysis",
      "rdfs:subClassOf": {
        "@id": "d3f:FileAnalysis"
      }
    }
```

### Technique (level 2: implementation)

```json
    {
      "@id": "d3f:FileContentRules",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:FileContentRules"
      ],
      "d3f:d3fend-id": "D3-FCR",
      "d3f:definition": "Employing a pattern matching rule language to analyze the content of files.",
      "d3f:kb-article": "## How it works\nRules, often called signatures, are used for both generic and targeted malware detection. The rules are usually expressed in a domain specific language (DSL), then deployed to software that scans files for matches. The rules are developed and broadly distributed by commercial vendors, or they are developed and deployed by enterprise security teams to address highly targeted or custom malware. Conceptually, there are public and private rule sets. Both leverage the same technology, but they are intended to detect different types of cyber adversaries.\n\n## Considerations\n* Patterns expressed in the DSLs range in their complexity. Some scanning engines support file parsing and normalization for high fidelity matching, others support only simple regular expression matching against raw file data. Engineers must make a trade-off in terms of:\n     * The fidelity of the matching capabilities in order to balance high recall with avoiding false positives,\n     * The computational load for scanning, and\n     * The resilience of the engine to deal with adversarial content presented in different forms-- content which in some cases is designed to exploit or defeat the scanning engines.\n * Signature libraries can become large over time and impact scanning performance.\n * Some vendors who sell signatures have to delete old signatures over time.\n * Simple signatures against raw content cannot match against encoded, encrypted, or sufficiently obfuscated content.\n\n## Implementations\n * YARA\n * ClamAV",
      "d3f:kb-reference": [
        {
          "@id": "d3f:Reference-ComputationalModelingAndClassificationOfDataStreams_CrowdstrikeInc"
        },
        {
          "@id": "d3f:Reference-DetectingScript-basedMalware_CrowdstrikeInc"
        },
        {
          "@id": "d3f:Reference-DistributedMeta-informationQueryInANetwork_Bit9Inc"
        },
        {
          "@id": "d3f:Reference-SystemAndMethodsThereofForLogicalIdentificationOfMaliciousThreatsAcrossAPluralityOfEnd-pointDevicesCommunicativelyConnectedByANetwork_PaloAltoNetworksIncCyberSecdoLtd"
        }
      ],
      "d3f:synonym": [
        "File Content Signatures",
        "File Signatures"
      ],
      "rdfs:label": "File Content Rules",
      "rdfs:subClassOf": {
        "@id": "d3f:FileContentAnalysis"
      }
    },
````

Mapped in same way a level 0.

Note, see here `"d3f:FileContentAnalysis"` is a direct link and the object does exist (so a relationship will be created)

### Shortfalls of this script

* not all d3fend objects are converted to STIX. Only matrix, tactics, techniques and artifacts (indicators) are created
* created and modified times are tied to version. Hence this script won't work properly with updates.

## External mappings

In the d3f3nd.json file are relationships to external knowledgebases.

For example,

```json
    {
      "@id": "d3f:T1550",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual"
      ],
      "d3f:accesses": {
        "@id": "d3f:AuthenticationService"
      },
      "d3f:attack-id": "T1550",
      "d3f:definition": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
      "rdfs:label": "Use Alternate Authentication Material",
      "rdfs:subClassOf": [
        {
          "@id": "d3f:DefenseEvasionTechnique"
        },
        {
          "@id": "d3f:LateralMovementTechnique"
        },
        {
          "@id": "_:N5fc8b9b1716f4ca1afb4ff65b6822484"
        }
      ]
    },
    {
      "@id": "_:N5fc8b9b1716f4ca1afb4ff65b6822484",
      "@type": "owl:Restriction",
      "owl:onProperty": {
        "@id": "d3f:accesses"
      },
      "owl:someValuesFrom": {
        "@id": "d3f:AuthenticationService"
      }
    },
```

These are not included in the bundle generated by this script.

We generate these in [Arango CTI Processor](https://github.com/muchdogesec/arango_cti_processor/). However, this script generates another json file ending with `-external-relationships.json`

The format of each relationship in this document is represented like so;

```json
    {
        "source": "d3f:T1550",
        "target": "d3f:AuthenticationService",
        "type": "d3f:accesses",
        "description": "Use Alternate Authentication Material accesses Authentication Service: An subject Use Alternate Authentication Material takes the action of reading from, writing into, or executing the stored information in the object Authentication Service. Reads, writes, and executes are specific cases of accesses."
    },
```