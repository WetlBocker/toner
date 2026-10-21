# numpy (it comes with pyqtgraph, for the graphs) sets up its maths library with a buffer for every processor core as soon as it
# is imported: about 750 MB of memory set aside on a 28-core PC. Toner only draws graphs with it, so one thread is plenty. This
# has to happen before numpy is first imported, which is always from a ui module.
import os as _os

_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
