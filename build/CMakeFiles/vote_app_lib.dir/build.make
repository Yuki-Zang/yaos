# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /workspaces/vote-Yuki-Zang

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /workspaces/vote-Yuki-Zang/build

# Include any dependencies generated for this target.
include CMakeFiles/vote_app_lib.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/vote_app_lib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/vote_app_lib.dir/flags.make

CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o: ../src/pkg/election.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o -c /workspaces/vote-Yuki-Zang/src/pkg/election.cxx

CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/pkg/election.cxx > CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.i

CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/pkg/election.cxx -o CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.s

CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o: ../src/pkg/voter.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o -c /workspaces/vote-Yuki-Zang/src/pkg/voter.cxx

CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/pkg/voter.cxx > CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.i

CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/pkg/voter.cxx -o CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.s

CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o: ../src/pkg/registrar.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o -c /workspaces/vote-Yuki-Zang/src/pkg/registrar.cxx

CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/pkg/registrar.cxx > CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.i

CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/pkg/registrar.cxx -o CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.s

CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o: ../src/pkg/tallyer.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o -c /workspaces/vote-Yuki-Zang/src/pkg/tallyer.cxx

CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/pkg/tallyer.cxx > CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.i

CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/pkg/tallyer.cxx -o CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.s

CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o: ../src/pkg/arbiter.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o -c /workspaces/vote-Yuki-Zang/src/pkg/arbiter.cxx

CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/pkg/arbiter.cxx > CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.i

CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/pkg/arbiter.cxx -o CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.s

CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o: ../src/drivers/cli_driver.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o -c /workspaces/vote-Yuki-Zang/src/drivers/cli_driver.cxx

CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/drivers/cli_driver.cxx > CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.i

CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/drivers/cli_driver.cxx -o CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.s

CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o: ../src/drivers/crypto_driver.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o -c /workspaces/vote-Yuki-Zang/src/drivers/crypto_driver.cxx

CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/drivers/crypto_driver.cxx > CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.i

CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/drivers/crypto_driver.cxx -o CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.s

CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o: ../src/drivers/db_driver.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o -c /workspaces/vote-Yuki-Zang/src/drivers/db_driver.cxx

CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/drivers/db_driver.cxx > CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.i

CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/drivers/db_driver.cxx -o CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.s

CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o: ../src/drivers/network_driver.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o -c /workspaces/vote-Yuki-Zang/src/drivers/network_driver.cxx

CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/drivers/network_driver.cxx > CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.i

CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/drivers/network_driver.cxx -o CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.s

CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o: CMakeFiles/vote_app_lib.dir/flags.make
CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o: ../src/drivers/repl_driver.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o -c /workspaces/vote-Yuki-Zang/src/drivers/repl_driver.cxx

CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/vote-Yuki-Zang/src/drivers/repl_driver.cxx > CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.i

CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/vote-Yuki-Zang/src/drivers/repl_driver.cxx -o CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.s

# Object files for target vote_app_lib
vote_app_lib_OBJECTS = \
"CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o" \
"CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o"

# External object files for target vote_app_lib
vote_app_lib_EXTERNAL_OBJECTS =

libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/pkg/election.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/pkg/voter.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/pkg/registrar.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/pkg/tallyer.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/pkg/arbiter.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/drivers/cli_driver.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/drivers/crypto_driver.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/drivers/db_driver.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/drivers/network_driver.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/src/drivers/repl_driver.cxx.o
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/build.make
libvote_app_lib.a: CMakeFiles/vote_app_lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/workspaces/vote-Yuki-Zang/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Linking CXX static library libvote_app_lib.a"
	$(CMAKE_COMMAND) -P CMakeFiles/vote_app_lib.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/vote_app_lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/vote_app_lib.dir/build: libvote_app_lib.a

.PHONY : CMakeFiles/vote_app_lib.dir/build

CMakeFiles/vote_app_lib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/vote_app_lib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/vote_app_lib.dir/clean

CMakeFiles/vote_app_lib.dir/depend:
	cd /workspaces/vote-Yuki-Zang/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /workspaces/vote-Yuki-Zang /workspaces/vote-Yuki-Zang /workspaces/vote-Yuki-Zang/build /workspaces/vote-Yuki-Zang/build /workspaces/vote-Yuki-Zang/build/CMakeFiles/vote_app_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/vote_app_lib.dir/depend

