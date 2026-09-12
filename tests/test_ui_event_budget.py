"""Event floods must yield without losing barriers, acknowledgements or results."""
from queue import Queue
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

from feathered_app.application.operations import OperationsMixin
from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state
requires_display = startup.requires_display


def host():
    value=SimpleNamespace(events=Queue(),active_operation=None,after=Mock(),
        _operation_status=Mock(),progress_var=Mock(),_log=Mock(),_worker_done=Mock(),
        _apply_download_plan=Mock(),_show_result=Mock())
    value._drain_events=lambda: OperationsMixin._drain_events(value)
    return value


def test_progress_burst_yields_before_consuming_all_events():
    value=host()
    for i in range(1000):value.events.put(('progress','building',i/1000))
    value._drain_events()
    assert not value.events.empty()
    assert value.after.call_args.args[0]<=10
    assert value.progress_var.set.call_count<100


def test_progress_coalescing_preserves_decision_and_completion_barriers():
    value=host();ack=Event();seen=[]
    value._apply_download_plan=lambda *args:seen.append('decision')
    value._worker_done=lambda *args:seen.append('done')
    value._show_result=lambda *args:seen.append('result')
    for i in range(220):value.events.put(('progress','work',i/220))
    value.events.put(('download_plan',[],[],ack))
    value.events.put(('result','bundle'))
    value.events.put(('done',True,''))
    while not value.events.empty():value._drain_events()
    assert ack.is_set() and seen==['decision','result','done']
    assert value.progress_var.set.call_args.args[0]==219/220*100


def test_failed_handler_acknowledges_and_does_not_strand_done():
    value=host();ack=Event()
    value._apply_download_plan=Mock(side_effect=RuntimeError('dialog closed'))
    value.events.put(('download_plan',[],[],ack))
    value.events.put(('done',False,'cancelled'))
    value._drain_events()
    assert ack.is_set()
    value._worker_done.assert_called_once_with(False,'cancelled',None)
    assert value.after.called


@requires_display
def test_real_gui_heartbeat_runs_before_a_progress_burst_finishes(application):
    window=application;seen=[]
    for i in range(5000):window.events.put(('progress','fixture',i/5000))
    window.after(0,window._drain_events)
    window.after(0,lambda:seen.append(window.events.qsize()))
    window.update()
    assert seen and seen[0]>0


def test_typed_obsolete_results_do_not_reach_handlers():
    from background_jobs import BackgroundJobs
    value=host();done=Queue();jobs=BackgroundJobs(done.put)
    value._background_query_jobs=jobs
    jobs.submit('versions',lambda cancel:('result','obsolete'))
    obsolete=done.get(timeout=5)
    jobs.submit('versions',lambda cancel:('result','current'))
    current=done.get(timeout=5)
    value.events.put(current);value.events.put(obsolete)
    value._drain_events()
    value._show_result.assert_called_once_with('current')
    jobs.close()


@requires_display
def test_destroying_window_cancels_discovery_ownership(application):
    window=application;entered=Event();exited=Event()
    def work(cancel):
        entered.set()
        try:assert cancel.wait(5)
        finally:exited.set()
        return ('result','obsolete')
    jobs=window._query_jobs();jobs.submit('fixture',work)
    assert entered.wait(5)
    window.destroy()
    assert exited.wait(5)
    try:jobs.submit('fixture',lambda cancel:None)
    except RuntimeError:pass
    else:raise AssertionError('destroyed window accepted new discovery')
