
# Defaults

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/d3fend2stix.json

# d3fend.json

## SCOs

The official d3fend repo contains the following mappings: https://d3fend.mitre.org/cad/docs/stix21mappings/

```txt
archive-ext d3f:ArchiveFile
artifact  d3f:DigitalArtifact
autonomous-system d3f:System
directory d3f:Directory
domain-name d3f:DomainName
email-addr  d3f:Identifier
email-message d3f:Email
file  d3f:File
http-request-ext  d3f:WebNetworkTraffic
ipv4-addr d3f:IPAddress
ipv6-addr d3f:IPAddress
icmp-ext  d3f:NetworkTraffic
mac-address d3f:Identifier
mutex d3f:DigitalArtifact
network-traffic d3f:NetworkTraffic
ntfs-ext  d3f:FileSystem
pdf-ext d3f:DocumentFile
process d3f:Process
raster-image-ext  d3f:DigitalArtifact
socket-ext  d3f:NetworkTraffic
software  d3f:Software
tcp-ext d3f:NetworkTraffic
url d3f:URL
unix-account-ext  d3f:UserAccount
user-account  d3f:UserAccount
windows-pebinary-ext  d3f:ExecutableBinary
windows-process-ext d3f:Process
windows-registry-ext  d3f:WindowsRegistryKey
windows-service-ext d3f:Service
x509-certificate  d3f:CertificateFile
```

Here is an example of `d3f:CertificateFile`

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

The problem is SCOs need values, they cannot be conceptual. As such, need to model as Indicators vs. SCOs. We also need to hack the pattern a bit.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "<TBD>",
  "modified": "<d3f:release-date>",
  "indicator_types": ["unknown"],
  "name": "<rdfs:label>",
  "description": "<d3f:definition>",
  "pattern": "<@id>",
  "pattern_type": "d3fend",
  "valid_from": "<created>",
  "external_references": [
    {
        "source_name": "mitre-d3f3nd",
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

### Relationship

On this part, see notes later;

```json
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

## Matrix

```json
{
  "type": "x-mitre-matrix",
  "id": "x-mitre-matrix--<UUID v5>",
  "created": "<TBD>",
  "modified": "<d3f:release-date>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",


    "description": "Below are the tactics and technique representing the MITRE ATT&CK Matrix for Enterprise. The Matrix contains information for the following platforms: Windows, macOS, Linux, AWS, GCP, Azure, Azure AD, Office 365, SaaS.",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/matrices/enterprise",
            "external_id": "enterprise-attack"
        }
    ],
    "modified": "2025-04-25T14:41:40.982Z",
    "name": "Enterprise ATT&CK",
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "tactic_refs": [
        "ALL_TACTICS"
    ],
    
}
```


## Tactics

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
	"type": "x-d3fend-tactic",
	"id": "x-d3fend-tactic--<UUID v5>",
	"created": "<TBD>",
	"modified": "<d3f:release-date>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"name": "<rdfs:label>",
	"description": "<d3f:definition>",
  "x_mitre_deprecated": false,
	"external_references": [
		{
	    	"source_name": "mitre-d3f3nd",
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

### Technique (level 0: general)

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
	"type": "attack-pattern",
	"id": "attack-pattern--<UUID v5>",
	"created": "<TBD>",
	"modified": "<d3f:release-date>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"name": "<rdfs:label>",
	"description": "<d3f:definition>\n<d3f:kb-article>",
	"aliases": [
		"<d3f:synonyms>"
	],
	"external_references": [
		{
	    	"source_name": "mitre-d3f3nd",
	    	"url": "https://d3fend.mitre.org/technique/<@id>",
	    	"external_id": "<d3f:d3fend-id>"
	  },
		{
	    	"description": "seeAlso",
	    	"url": "<@id>"
	  },
		{
	    	"description": "seeAlso",
	    	"url": "<@id>"
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

### Relationships

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

Here the link to a tactic (`d3f:Detect`) and Indicator (`d3f:File`) is shown.

Note, there is also a direct link from this object `d3f:DefensiveTechnique`. In this case , we should try and create a relationship with type `subClassOf`.

NOTE, some references like this will not exist (`d3f:DefensiveTechnique` is one). In such cases, we should ignore the missing object, and skip the generation of the relationship (both for direct and indirect)

Relationships are created like so;

```json
{
  "type": "relationship",
  "id": "relationship--<UUID v5>",
  "created": "<source.created>",
  "modified": "<target.created>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "relationship_type": "<owl:onProperty.@id> (ref) OR subClassOf (direct)",
  "source_ref": "<source.id>",
  "target_ref": "<target.id>",
  "description": "<source.name> <rleationship type> <target.name>",
  "external_references": [
    {
        "source_name": "mitre-d3f3nd",
        "url": "https://d3fend.mitre.org/technique/<source.@id>",
        "external_id": "<d3f:d3fend-id>"
    },
    {
        "source_name": "mitre-d3f3nd",
        "url": "https://d3fend.mitre.org/technique/<target.@id>",
        "external_id": "<d3f:d3fend-id>"
    }
  ],
  "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--6923e7d4-e142-508c-aefc-b5f4dd27dc22"
  ]
```

### Technique (level 1: specific)

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

Mapped in same way a level 0.

Note, see here `"d3f:FileAnalysis"` is a direct link and the object does exist (so a relationship will be created)

### Technique (level 1: specific)

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