"""First-party synthetic sample, generated without patient or credential data."""


def synthetic_sample():
    return {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "AuditEvent",
                    "id": f"synthetic-access-{i:02}",
                    "type": {
                        "system": "http://dicom.nema.org/resources/ontology/DCM",
                        "code": "110110",
                    },
                    "recorded": f"2026-11-16T10:00:{i:02}Z",
                    "action": "R",
                    "outcome": "0",
                    "agent": [
                        {
                            "who": {"reference": "Practitioner/synthetic-analyst"},
                            "requestor": True,
                        }
                    ],
                    "source": {
                        "observer": {"reference": "Device/synthetic-workstation"}
                    },
                    "entity": [
                        {"what": {"reference": f"Patient/synthetic-patient-{i:02}"}}
                    ],
                }
            }
            for i in range(30)
        ],
    }
