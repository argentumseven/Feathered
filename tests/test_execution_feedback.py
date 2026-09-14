"""Keep decision and event behavior while narrowing execution capabilities."""
from queue import Queue
from threading import Event
from unittest.mock import Mock

import pytest
import core
from feathered_app.build_service_host import BuildServiceHost
from feathered_app.build_services import BuildServices
from feathered_app.build_outcome import BuildStatus
from feathered_app.execution_feedback import bind_execution_feedback, complete, mirror_reporter


def test_feedback_preserves_order_and_mirror_progress_and_warning_collection():
    trace=[]
    class Sink:
        def put(self,event):trace.append(event)
    reporter=core.Reporter(log=lambda message:trace.append(('log',message)),
                           progress=lambda label,value:trace.append(('progress',label,value)))
    host=BuildServiceHost(BuildServices(reporter,events=Sink(),
        download_plan_sink=lambda count,size:trace.append(('plan',count,size))))
    feedback=bind_execution_feedback(host)
    feedback.reporter.log('start')
    feedback.publish_download_plan(2,10)
    fork=mirror_reporter(host,feedback.reporter,'origin',.5,.5)
    fork.progress('transfer',.4)
    fork.transfer('demo',5,10)
    fork.item('demo','done',bytes=10)
    fork.warn('check upstream')
    result=complete(feedback.events,True,'finished','bundle')
    assert trace==[('log','start'),('plan',2,10),('progress','transfer',.7),
        ('transfer','origin|demo',5,10),('item','origin|demo','done',{'bytes':10}),
        ('log','WARNING: check upstream'),
        ('done',True,'finished','bundle')]
    assert feedback.reporter.warnings==['check upstream']
    assert result.status is BuildStatus.SUCCESS


@pytest.mark.parametrize('ok,status',[(True,BuildStatus.SUCCESS),(False,BuildStatus.FAILED),('cancelled',BuildStatus.CANCELLED)])
def test_terminal_contract_emits_once_and_retains_optional_path_shape(ok,status):
    events=Queue();outcome=complete(events,ok,'message')
    assert outcome.status is status and outcome.output_path is None
    assert events.get_nowait()==('done',ok,'message')
    assert events.empty()


def test_missing_policies_still_decline_and_cancellation_uses_capability():
    host=BuildServiceHost(BuildServices(core.Reporter()))
    feedback=bind_execution_feedback(host)
    assert not feedback.decide('title','body',wait_status='waiting')
    assert not feedback.confirm_warnings(['warning'])
    assert not feedback.confirm_conflicts(['conflict'])
    host.request_cancel()
    with pytest.raises(core.Cancelled):feedback.reporter.check_cancel()


def test_each_binding_has_independent_progress_and_warning_state():
    host=BuildServiceHost(BuildServices(core.Reporter()))
    one=bind_execution_feedback(host);two=bind_execution_feedback(host)
    one.reporter.warn('one');one.reporter.phase(.5,.5)
    assert two.reporter.warnings==[]
    assert two.reporter._phase_start==0


def test_headless_feedback_does_not_queue_chunk_progress_without_an_event_sink():
    host=BuildServiceHost(BuildServices(core.Reporter()))
    feedback=bind_execution_feedback(host)
    feedback.reporter.transfer('demo', 1024, 4096)
    assert host.events.empty()
