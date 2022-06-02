#!/bin/bash

setup() {
  cd ./WFDG-Generator/3rdparty || exit
  if [ ! -d "pybind11" ];then
     git clone git@github.com:pybind/pybind11.git
  fi
  cd ..
  mkdir "build"
  cd ./build || exit
  cmake ..
  make -j4
  for file in ./lib/*
  do
    if [[ $file == ./lib/wfdg_generator* ]]; then
      cp "$file" ../../genWFDG/
    fi
  done

  echo "Configuration completed."
}

echo "Configuring VulExplorer..."
echo "You need to install the following dependencies:"
echo "CMake(>=3.14), Git, clang(9.0.0), LLVM"


read -r -p "Have you installed all dependencies? [Y/N] " input

case $input in
    [yY][eE][sS]|[yY])
        setup
        ;;
    *)
        echo "Exit"
        exit 1
        ;;
esac