"""Malformed saved settings must never become permissive execution controls."""
from dataclasses import replace
import json
from unittest.mock import Mock
import pytest
from build_spec import BuildSpec, SourceSpec, RepositoryRecord
from feathered_app.build_api import prepare_build, PreparationInputs
from feathered_app.build_preparation import PreparationRejected
from feathered_app.build_services import BuildServices
import core

@pytest.mark.parametrize('value', ['false',0,1,None,[],{}])
def test_repository_boolean_types_are_rejected(value):
    for field in ('enabled','allow_unverified_index'):
        with pytest.raises(ValueError,match=r'sources.repositories\[0\].'+field):
            BuildSpec.from_dict({'sources':{'repositories':[{field:value}]}})

@pytest.mark.parametrize('payload,path', [([], 'spec'),({'spec_version':None},'spec_version'),
    ({'spec_version':0},'spec_version'),({'spec_version':True},'spec_version'),
    ({'target':[]},'target'),({'target':{'release':10}},'target.release'),
    ({'sources':{'repositories':None}},'sources.repositories'),
    ({'content':{'exact_packages':['demo']}},r'content.exact_packages\[0\]'),
    ({'sources':{'repositories':[{'evidence_relationship_hints':[['a',False]]}]}},'evidence_relationship_hints'),
    ({'spec_version':2,'target':{'api_server_versions':4}},'target.api_server_versions')])
def test_bad_shapes_have_field_diagnostics(payload,path):
    with pytest.raises(ValueError,match=path): BuildSpec.from_dict(payload)

def test_valid_draft_optional_fields_and_unknown_keys_remain_compatible():
    for version in (1,2,3):
        spec=BuildSpec.from_dict({'spec_version':version,'target':{'release':'','future':True},'sources':{'required_signature_vendors':None}})
        assert spec.target.release=='' and spec.sources.required_signature_vendors is None
        assert BuildSpec.from_json(spec.to_json())==spec

def test_direct_api_rejects_wrong_dataclass_fields_before_any_work(monkeypatch):
    spec=BuildSpec(sources=SourceSpec(repositories=(RepositoryRecord(allow_unverified_index='false'),)))
    services=BuildServices(core.Reporter())
    with pytest.raises(PreparationRejected,match='allow_unverified_index'):
        prepare_build(spec,services)

def test_direct_runtime_configuration_has_same_validation_as_json():
    with pytest.raises(PreparationRejected,match='Resolution pass budget'):
        prepare_build(BuildSpec(),BuildServices(core.Reporter()),PreparationInputs(resolution_pass_budget=True))

def test_cli_malformed_shape_is_invalid_request_without_traceback(tmp_path,capsys):
    from feathered_cli import main
    path=tmp_path/'bad.json';path.write_text('[]')
    assert main(['build','--spec',str(path)])==5
    err=capsys.readouterr().err
    assert 'spec' in err and 'Traceback' not in err
