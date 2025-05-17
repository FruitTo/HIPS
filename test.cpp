#include "./include/BS_thread_pool.hpp"
#include <future>             // std::future
#include <iostream>           // std::cout

int the_answer()
{
    return 42;
}

int main()
{
    BS::thread_pool pool(4);
    std::future<int> my_future = pool.submit_task(the_answer);
    std::cout << my_future.get() << '\n';
}