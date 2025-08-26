# Prerequisites:
+ A working ns-3 (3.35), built with examples enabled.
+ Compatible with C++14 compiler.
# Build: 
+ CXX=g++-12 CC=gcc-12 ./waf configure --disable-werror --enable-examples --enable-tests
+ ./waf build or ./waf -j$(nproc)
# Run the example:
### General form
./waf --run "tesla-topology-example --topology=<broadcast|star|mesh|ring> --verbose=true"
# Examples:

### Broadcast where node 0 talks to everyone else
./waf --run "tesla-topology-example --topology=broadcast --verbose=true"

### Star topology
./waf --run "tesla-topology-example --topology=star --verbose=true"

### Full mesh topology (each node sends to every other node)
./waf --run "tesla-topology-example --topology=mesh --verbose=true"

### Ring topology
./waf --run "tesla-topology-example --topology=ring --verbose=true"

# Visualize with NetAnim:
The example writes an animation XML file (It can be used to verify what’s really happening), e.g.:
+ tesla-broadcast.xml
+ tesla-star.xml
+ tesla-mesh.xml

## Install NetAnim:
+ Clone latest version of NetAnim from http://code.nsnam.org/netanim
+ cd netanim
+ make clean
+ qmake NetAnim.pro
+ make
