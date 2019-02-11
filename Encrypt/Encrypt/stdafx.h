// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <gtest/gtest.h>

#if defined(_MT)
#if defined(_DEBUG)
#pragma comment(lib, "gtestd.lib")
#else 
#pragma comment(lib, "gtest.lib")
#endif
#endif




// TODO:  在此处引用程序需要的其他头文件
