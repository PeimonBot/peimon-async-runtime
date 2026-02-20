#pragma once
// C++20 coroutine Task<T> awaitable; compiles with C++20 and C++23.

#include "peimon/event_loop.hpp"
#include <coroutine>
#include <exception>
#include <utility>

namespace peimon {

namespace detail {

inline EventLoop*& current_loop_ref() {
    thread_local EventLoop* loop = nullptr;
    return loop;
}

}  // namespace detail

inline EventLoop* get_event_loop() {
    return detail::current_loop_ref();
}

inline void set_event_loop(EventLoop* loop) {
    detail::current_loop_ref() = loop;
}

template <typename T>
class Task;

template <typename T>
struct TaskPromise {
    T value_;
    std::exception_ptr exception_;
    std::coroutine_handle<> continuation_{nullptr};

    Task<T> get_return_object() noexcept;
    std::suspend_always initial_suspend() noexcept { return {}; }
    void return_value(T value) noexcept(std::is_nothrow_move_constructible_v<T>) {
        value_ = std::move(value);
    }
    void unhandled_exception() noexcept { exception_ = std::current_exception(); }

    std::suspend_always final_suspend() noexcept {
        if (continuation_) {
            EventLoop* loop = get_event_loop();
            if (loop) {
                loop->queue_in_loop([h = continuation_]() { h.resume(); });
            } else {
                continuation_.resume();
            }
        }
        return {};
    }

    void set_continuation(std::coroutine_handle<> h) noexcept { continuation_ = h; }
};

template <>
struct TaskPromise<void> {
    std::exception_ptr exception_;
    std::coroutine_handle<> continuation_{nullptr};

    Task<void> get_return_object() noexcept;
    std::suspend_always initial_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() noexcept { exception_ = std::current_exception(); }

    std::suspend_always final_suspend() noexcept {
        if (continuation_) {
            EventLoop* loop = get_event_loop();
            if (loop) {
                loop->queue_in_loop([h = continuation_]() { h.resume(); });
            } else {
                continuation_.resume();
            }
        }
        return {};
    }

    void set_continuation(std::coroutine_handle<> h) noexcept { continuation_ = h; }
};

template <typename T>
class TaskAwaiter;

template <typename T>
class Task {
public:
    using promise_type = TaskPromise<T>;
    friend class TaskAwaiter<T>;

    Task() noexcept = default;
    Task(Task&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    ~Task() {
        if (handle_) handle_.destroy();
    }

    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            if (handle_) handle_.destroy();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    bool valid() const noexcept { return handle_ != nullptr; }

    void start(EventLoop& loop) {
        if (!handle_) return;
        set_event_loop(&loop);
        loop.queue_in_loop([this]() {
            if (handle_ && !handle_.done()) handle_.resume();
        });
    }

    void start(EventLoop* loop) {
        if (loop) start(*loop);
    }

private:
    friend struct TaskPromise<T>;
    explicit Task(std::coroutine_handle<promise_type> h) noexcept : handle_(h) {}

    std::coroutine_handle<promise_type> handle_{nullptr};
};

template <typename T>
Task<T> TaskPromise<T>::get_return_object() noexcept {
    return Task<T>(std::coroutine_handle<TaskPromise<T>>::from_promise(*this));
}

inline Task<void> TaskPromise<void>::get_return_object() noexcept {
    return Task<void>(std::coroutine_handle<TaskPromise<void>>::from_promise(*this));
}

template <typename T>
class TaskAwaiter {
public:
    explicit TaskAwaiter(Task<T>&& t) noexcept : task_(std::move(t)) {}

    bool await_ready() const noexcept {
        return !task_.valid() || task_.handle_.done();
    }

    void await_suspend(std::coroutine_handle<> h) noexcept {
        task_.handle_.promise().set_continuation(h);
        EventLoop* loop = get_event_loop();
        if (loop) {
            loop->queue_in_loop([this]() {
                if (task_.handle_ && !task_.handle_.done()) task_.handle_.resume();
            });
        } else {
            if (task_.handle_ && !task_.handle_.done()) task_.handle_.resume();
        }
    }

    T await_resume() {
        auto& promise = task_.handle_.promise();
        if (promise.exception_) std::rethrow_exception(promise.exception_);
        if constexpr (!std::is_void_v<T>) {
            return std::move(promise.value_);
        } else {
            return;
        }
    }

private:
    Task<T> task_;
};

template <typename T>
inline TaskAwaiter<T> operator co_await(Task<T>&& task) noexcept {
    return TaskAwaiter<T>(std::move(task));
}

}  // namespace peimon
