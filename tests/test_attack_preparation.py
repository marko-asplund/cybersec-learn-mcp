from copy import deepcopy

from scripts.prepare_attack import prepare_techniques


def technique(technique_id='T1078.004'):
    return {
        'type': 'attack-pattern', 'id': 'attack-pattern--fixture',
        'name': 'Cloud Accounts', 'description': 'Original text (Citation: example).',
        'x_mitre_platforms': ['IaaS'], 'x_mitre_is_subtechnique': True,
        'x_mitre_version': '2.0', 'modified': '2026-05-12T00:00:00Z',
        'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}],
        'external_references': [
            {'source_name': 'mitre-attack', 'external_id': technique_id,
             'url': 'https://attack.mitre.org/techniques/T1078/004/'},
            {'source_name': 'example', 'url': 'https://example.com/reference'},
        ],
    }


def test_preserves_original_text_and_citations():
    obj = technique()
    original = deepcopy(obj)
    prepared, excluded = prepare_techniques({'objects': [obj, {'type': 'relationship'}]})
    record = prepared['T1078.004']
    assert record['description'] == obj['description']
    assert record['external_references'] == obj['external_references']
    assert record['tactics'] == ['initial-access']
    assert record['is_subtechnique'] is True
    assert excluded == {}
    assert obj == original


def test_excludes_revoked_and_deprecated_techniques():
    revoked = technique('T1000') | {'revoked': True}
    deprecated = technique('T1001') | {'x_mitre_deprecated': True}
    prepared, excluded = prepare_techniques({'objects': [revoked, technique(), deprecated]})
    assert list(prepared) == ['T1078.004']
    assert excluded == {'T1000': 'revoked', 'T1001': 'deprecated'}
