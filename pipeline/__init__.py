"""pipeline — the runtime sequence CIPHER actually runs (SDD D3).

main.py constructs components and hands them to Pipeline; it contains no
orchestration logic itself. Pipeline owns the background-thread capture
loop and the per-packet fault isolation described in SDD Section 12.
"""
