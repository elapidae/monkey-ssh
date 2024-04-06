#pragma once

#include <map>
#include "vbyte_buffer.h"
#include "vlog.h"

//=======================================================================================
struct Error
{
    bool err = false;
    std::string msg;
};
struct KeyVal
{
    //-----------------------------------------------------------------------------------
    using string = std::string;
    //-----------------------------------------------------------------------------------
    string key, val;
    //-----------------------------------------------------------------------------------
    using Map = std::map<string, string>;
    //--
    static Map split_heap(const vbyte_buffer& heap);
    //-----------------------------------------------------------------------------------
    static KeyVal split_one(const vbyte_buffer& bb);
    //-----------------------------------------------------------------------------------
};
struct Heap
{
    using heap_or_err = std::tuple<bool, KeyVal::Map>;
    static heap_or_err parse( vbyte_buffer* bb );
};
//=======================================================================================
