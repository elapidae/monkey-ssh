#include "keyval.h"

using namespace std;

//=======================================================================================
KeyVal::Map KeyVal::split_heap(const vbyte_buffer &heap)
{
    Map res;
    auto lines = heap.split('\n');
    for ( auto && line: lines )
    {
        auto kv = KeyVal::split_one(line);
        res[kv.key] = kv.val;
    }
    return res;
}
//=======================================================================================
KeyVal KeyVal::split_one(const vbyte_buffer &bb)
{
    KeyVal res;
    auto list = bb.split(':');
    if (list.size() != 2)
        throw verror("Bad KeyVal split '", bb, "'");

    res.key = list.at(0);
    res.val = list.at(1);
    return res;
}
//=======================================================================================


//=======================================================================================
Heap::heap_or_err Heap::parse( vbyte_buffer *buffer )
{
    auto nn_pos = buffer->str().find("\n\n");
    if ( nn_pos == string::npos )
        return{false,{}};

    auto _heap = buffer->left(nn_pos);
    buffer->chop_front( _heap.size() + 2 ); // 2 -- size of \n\n

    auto heap = KeyVal::split_heap( _heap );

    return {true,heap};
}
//=======================================================================================
