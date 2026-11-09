// JSON Schemas the feed validates against at runtime. Copies of
// docs/specs/desktop-feed-manifest.schema.json and
// docs/specs/desktop-feed-envelope.schema.json (test/desktop-feed.test.ts
// asserts they stay identical), embedded so the built server does not read
// docs/ at runtime. DRAFT_CREATE_SCHEMA is the OpenAPI component
// DesktopFeedDraftCreate with DesktopFeedExpectedAsset inlined and the x-
// annotations dropped (also asserted by test/desktop-feed.test.ts).
/* eslint-disable */

export const MANIFEST_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:agent-relay:desktop-feed:manifest:1",
  "title": "Desktop feed signed manifest, schema 1",
  "$comment": "Status: implemented (relaycontrol docs/desktop-feed.md; src/desktop-feed/schemas.ts embeds this file). Source: relay-desktop docs/enterprise-distribution.md at 21e61026, section Signed manifest. Self-contained: no external references. Cross-field rules a schema cannot state (unique asset ids and names, key_id naming the same profile, version newer than installed) are listed in docs/desktop-feed.md.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "profile",
    "channel",
    "version",
    "published_at",
    "notes",
    "download_hosts",
    "assets"
  ],
  "properties": {
    "schema": {
      "description": "Document schema. A client refuses a schema it does not know.",
      "const": 1
    },
    "profile": {
      "description": "Opaque profile id. Must equal the build's compiled id.",
      "type": "string",
      "pattern": "^[a-z0-9]{1,32}$"
    },
    "channel": {
      "description": "Must equal the channel the client asked for.",
      "enum": [
        "stable",
        "beta"
      ]
    },
    "version": {
      "description": "YYYY.M.N on stable, YYYY.M.N-beta.N on beta.",
      "type": "string",
      "pattern": "^[0-9]{4}\\.(?:[1-9]|1[0-2])\\.(?:0|[1-9][0-9]*)(?:-beta\\.(?:0|[1-9][0-9]*))?$"
    },
    "published_at": {
      "description": "RFC 3339 UTC, whole seconds, set by the signing Cloud at publish.",
      "type": "string",
      "format": "date-time",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    },
    "notes": {
      "description": "Markdown release notes from release-notes.py.",
      "type": "string",
      "maxLength": 65536
    },
    "download_hosts": {
      "description": "The only hosts a signed download URL may point at (DNS names, lower case, no port, no IP literal). Empty means streamed downloads from the site only.",
      "type": "array",
      "maxItems": 8,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "maxLength": 253,
        "pattern": "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
      }
    },
    "assets": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "uniqueItems": true,
      "items": {
        "$ref": "#/$defs/asset"
      }
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "channel": {
            "const": "beta"
          }
        },
        "required": [
          "channel"
        ]
      },
      "then": {
        "properties": {
          "version": {
            "type": "string",
            "pattern": "-beta\\.(?:0|[1-9][0-9]*)$"
          }
        }
      },
      "else": {
        "properties": {
          "version": {
            "type": "string",
            "not": {
              "type": "string",
              "pattern": "-beta\\."
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "asset": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "name",
        "platform",
        "arch",
        "kind",
        "size",
        "sha256"
      ],
      "properties": {
        "id": {
          "description": "Opaque, assigned by the signing Cloud at upload; used by the download endpoints. Looked up only within the requesting profile.",
          "type": "string",
          "pattern": "^a_[0-9A-Za-z]{1,64}$"
        },
        "name": {
          "description": "Today's asset name, one path segment: dot-separated runs of [A-Za-z0-9_+-], so no '/', no leading dot and no '..'. The storage key is always profiles/<profile>/releases/<version>/<name>.",
          "type": "string",
          "maxLength": 255,
          "pattern": "^[A-Za-z0-9][A-Za-z0-9_+-]*(?:\\.[A-Za-z0-9_+-]+)*$"
        },
        "platform": {
          "enum": [
            "macOS",
            "Linux",
            "Windows"
          ]
        },
        "arch": {
          "enum": [
            "arm64",
            "x64"
          ]
        },
        "os_floor": {
          "description": "macOS major floor; absent on the unfloored updater-bridge name and on every non-macOS asset.",
          "type": "integer",
          "minimum": 10,
          "maximum": 99
        },
        "kind": {
          "enum": [
            "image",
            "tarball",
            "zip",
            "deb",
            "setup",
            "probe",
            "install-script"
          ]
        },
        "size": {
          "description": "Bytes. A download larger than this is cut off.",
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "sha256": {
          "description": "Lower-case hex, 64 characters.",
          "type": "string",
          "pattern": "^[0-9a-f]{64}$"
        }
      },
      "dependentSchemas": {
        "os_floor": {
          "properties": {
            "platform": {
              "const": "macOS"
            }
          }
        }
      }
    }
  }
} as const;

export const ENVELOPE_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:agent-relay:desktop-feed:envelope:1",
  "title": "Desktop feed envelope (signed manifest as served)",
  "$comment": "Status: implemented (relaycontrol docs/desktop-feed.md; src/desktop-feed/schemas.ts embeds this file). Self-contained: $defs.manifest and $defs.asset are copies of desktop-feed-manifest.schema.json (the relaycontrol test suite keeps them identical). The signature is Ed25519 (RFC 8032) over the UTF-8 bytes of the RFC 8785 (JCS) canonical form of `manifest` as received.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "manifest",
    "signature",
    "key_id"
  ],
  "properties": {
    "manifest": {
      "$ref": "#/$defs/manifest"
    },
    "signature": {
      "description": "Ed25519 signature, 64 bytes, base64url without padding (86 characters; the last one carries 2 data bits).",
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{85}[AQgw]$"
    },
    "key_id": {
      "description": "fk_<profile>_<label>. Selects the public key; a build carries one key and refuses any other key_id. The <profile> part must equal manifest.profile.",
      "type": "string",
      "pattern": "^fk_[a-z0-9]{1,32}_[a-z0-9]{1,16}$"
    }
  },
  "$defs": {
    "manifest": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schema",
        "profile",
        "channel",
        "version",
        "published_at",
        "notes",
        "download_hosts",
        "assets"
      ],
      "properties": {
        "schema": {
          "description": "Document schema. A client refuses a schema it does not know.",
          "const": 1
        },
        "profile": {
          "description": "Opaque profile id. Must equal the build's compiled id.",
          "type": "string",
          "pattern": "^[a-z0-9]{1,32}$"
        },
        "channel": {
          "description": "Must equal the channel the client asked for.",
          "enum": [
            "stable",
            "beta"
          ]
        },
        "version": {
          "description": "YYYY.M.N on stable, YYYY.M.N-beta.N on beta.",
          "type": "string",
          "pattern": "^[0-9]{4}\\.(?:[1-9]|1[0-2])\\.(?:0|[1-9][0-9]*)(?:-beta\\.(?:0|[1-9][0-9]*))?$"
        },
        "published_at": {
          "description": "RFC 3339 UTC, whole seconds, set by the signing Cloud at publish.",
          "type": "string",
          "format": "date-time",
          "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
        },
        "notes": {
          "description": "Markdown release notes from release-notes.py.",
          "type": "string",
          "maxLength": 65536
        },
        "download_hosts": {
          "description": "The only hosts a signed download URL may point at (DNS names, lower case, no port, no IP literal). Empty means streamed downloads from the site only.",
          "type": "array",
          "maxItems": 8,
          "uniqueItems": true,
          "items": {
            "type": "string",
            "maxLength": 253,
            "pattern": "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
          }
        },
        "assets": {
          "type": "array",
          "minItems": 1,
          "maxItems": 64,
          "uniqueItems": true,
          "items": {
            "$ref": "#/$defs/asset"
          }
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "channel": {
                "const": "beta"
              }
            },
            "required": [
              "channel"
            ]
          },
          "then": {
            "properties": {
              "version": {
                "type": "string",
                "pattern": "-beta\\.(?:0|[1-9][0-9]*)$"
              }
            }
          },
          "else": {
            "properties": {
              "version": {
                "type": "string",
                "not": {
                  "type": "string",
                  "pattern": "-beta\\."
                }
              }
            }
          }
        }
      ]
    },
    "asset": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "name",
        "platform",
        "arch",
        "kind",
        "size",
        "sha256"
      ],
      "properties": {
        "id": {
          "description": "Opaque, assigned by the signing Cloud at upload; used by the download endpoints. Looked up only within the requesting profile.",
          "type": "string",
          "pattern": "^a_[0-9A-Za-z]{1,64}$"
        },
        "name": {
          "description": "Today's asset name, one path segment: dot-separated runs of [A-Za-z0-9_+-], so no '/', no leading dot and no '..'. The storage key is always profiles/<profile>/releases/<version>/<name>.",
          "type": "string",
          "maxLength": 255,
          "pattern": "^[A-Za-z0-9][A-Za-z0-9_+-]*(?:\\.[A-Za-z0-9_+-]+)*$"
        },
        "platform": {
          "enum": [
            "macOS",
            "Linux",
            "Windows"
          ]
        },
        "arch": {
          "enum": [
            "arm64",
            "x64"
          ]
        },
        "os_floor": {
          "description": "macOS major floor; absent on the unfloored updater-bridge name and on every non-macOS asset.",
          "type": "integer",
          "minimum": 10,
          "maximum": 99
        },
        "kind": {
          "enum": [
            "image",
            "tarball",
            "zip",
            "deb",
            "setup",
            "probe",
            "install-script"
          ]
        },
        "size": {
          "description": "Bytes. A download larger than this is cut off.",
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "sha256": {
          "description": "Lower-case hex, 64 characters.",
          "type": "string",
          "pattern": "^[0-9a-f]{64}$"
        }
      },
      "dependentSchemas": {
        "os_floor": {
          "properties": {
            "platform": {
              "const": "macOS"
            }
          }
        }
      }
    }
  }
} as const;

export const DRAFT_CREATE_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:agent-relay:desktop-feed:draft-create:1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "channel",
    "notes",
    "expected_assets"
  ],
  "properties": {
    "version": {
      "type": "string",
      "pattern": "^[0-9]{4}\\.(?:[1-9]|1[0-2])\\.(?:0|[1-9][0-9]*)(?:-beta\\.(?:0|[1-9][0-9]*))?$"
    },
    "channel": {
      "enum": [
        "stable",
        "beta"
      ]
    },
    "notes": {
      "type": "string",
      "maxLength": 65536
    },
    "expected_assets": {
      "description": "The complete asset set of the release. Required and non-empty; names unique.",
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "name",
          "platform",
          "arch",
          "kind",
          "size",
          "sha256"
        ],
        "properties": {
          "name": {
            "type": "string",
            "maxLength": 255,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_+-]*(?:\\.[A-Za-z0-9_+-]+)*$"
          },
          "platform": {
            "enum": [
              "macOS",
              "Linux",
              "Windows"
            ]
          },
          "arch": {
            "enum": [
              "arm64",
              "x64"
            ]
          },
          "os_floor": {
            "type": "integer",
            "minimum": 10,
            "maximum": 99
          },
          "kind": {
            "enum": [
              "image",
              "tarball",
              "zip",
              "deb",
              "setup",
              "probe",
              "install-script"
            ]
          },
          "size": {
            "type": "integer",
            "minimum": 1,
            "maximum": 9007199254740991
          },
          "sha256": {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$"
          }
        },
        "dependentSchemas": {
          "os_floor": {
            "properties": {
              "platform": {
                "const": "macOS"
              }
            }
          }
        }
      }
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "channel": {
            "const": "beta"
          }
        },
        "required": [
          "channel"
        ]
      },
      "then": {
        "properties": {
          "version": {
            "type": "string",
            "pattern": "-beta\\.(?:0|[1-9][0-9]*)$"
          }
        }
      },
      "else": {
        "properties": {
          "version": {
            "type": "string",
            "not": {
              "type": "string",
              "pattern": "-beta\\."
            }
          }
        }
      }
    }
  ]
} as const;
