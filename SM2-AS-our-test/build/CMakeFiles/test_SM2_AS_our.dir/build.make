# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CMake.app/Contents/bin/cmake

# The command to remove a file.
RM = /Applications/CMake.app/Contents/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build"

# Include any dependencies generated for this target.
include CMakeFiles/test_SM2_AS_our.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test_SM2_AS_our.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_SM2_AS_our.dir/flags.make

CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o: CMakeFiles/test_SM2_AS_our.dir/flags.make
CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o: ../test/test_SM2_AS_our.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o -c "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/test/test_SM2_AS_our.cpp"

CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/test/test_SM2_AS_our.cpp" > CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.i

CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/test/test_SM2_AS_our.cpp" -o CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.s

# Object files for target test_SM2_AS_our
test_SM2_AS_our_OBJECTS = \
"CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o"

# External object files for target test_SM2_AS_our
test_SM2_AS_our_EXTERNAL_OBJECTS =

test_SM2_AS_our: CMakeFiles/test_SM2_AS_our.dir/test/test_SM2_AS_our.cpp.o
test_SM2_AS_our: CMakeFiles/test_SM2_AS_our.dir/build.make
test_SM2_AS_our: /usr/local/lib/libssl.dylib
test_SM2_AS_our: /usr/local/lib/libcrypto.dylib
test_SM2_AS_our: CMakeFiles/test_SM2_AS_our.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_SM2_AS_our"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_SM2_AS_our.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_SM2_AS_our.dir/build: test_SM2_AS_our

.PHONY : CMakeFiles/test_SM2_AS_our.dir/build

CMakeFiles/test_SM2_AS_our.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_SM2_AS_our.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_SM2_AS_our.dir/clean

CMakeFiles/test_SM2_AS_our.dir/depend:
	cd "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test" "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test" "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build" "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build" "/Users/tbb/Desktop/Adaptor Signature-适配器签名-讨论班-新方向-Post-Quantum Adaptor Signatures and Payment Channel Networks2020-845/SM2-based Adaptor Signature/all-code-SM2/SM2-code-20220707/SM2-AS-our-test/build/CMakeFiles/test_SM2_AS_our.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/test_SM2_AS_our.dir/depend

