module;
#include <Windows.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <thread>
#include <memory>
#include <optional>

export module WinKernel.Manager;

import WinKernel.Process;
import WinKernel.Types;

export namespace WinKernel::Manager {
	//template은 컴파일러에게 자료형은 나중에 정할테니 일단 구조대로 동작하게 하라는 것입니다. (자료형에 얽매이지 않고 재사용 가능한 코드를 만들기 위한 틀)
	//typename T에서 T는 특정 자료형을 T라는 기호라고 사용하겠다며 컴파일러에게 알려줍니다. typename T에서 T는 그냥 임의로 개발자가 정하는 이름입니다. 
	template <typename T> 
	class TaskQueue {
	private:
		//std::queue<T>는 T라는 자료형의 데이터를 저장하는 queue라는 의미입니다. 만약 TaskQueue<int>로 사용하면 queue<T>는 std::queue<int> 처럼 정수를 담는 큐가 됩니다.
		std::queue<T> queue_;

		//mutable은 변할 수 있다는 것을 의미합니다. const 함수 안에서도 이 변수 만큼은 수정할 수 있게 해달라는 것입니다.
		//std::mutex는 int가 숫자를 담듯이 자물쇠의 상태를 담는 C++ 객체입니다. .lock()과 .unlock()이라는 동작을 가집니다.
		mutable std::mutex mutex_;

		//condition_variable은 조건 변수라는 뜻입니다. 멀티스레드 환경에서 스레드끼리 신호를 주고받으며 대기/깨어남을 조율하며 동기화하는 도구입니다.
		std::condition_variable cv_;
		bool stopFlag_{ false };
	
	//Thread-Safe Task Queue
	public:
		TaskQueue() = default;
		~TaskQueue() { Clear(); }

		//복사 및 이동 방지를 합니다. 스레드 동기화 객체 안전성을 확보합니다.

		//복사 생성자를 금지합니다.
		//생성자 안에 클래스와 같은 타입의 객체 원본을 읽기 전용으로 참조할 경우, 다시 말해 기존 객체를 복사해서 새 객체를 만들때를 의미합니다.
		TaskQueue(const TaskQueue&) = delete;
		//operator는 이미 만들어진 객체에 다른 객체의 값을 대입할 때 호출되는 함수입니다.
		//operator=는 = 연산자 우변에 들어올 값으로 TaskQueue 타입의 객체를 받겠다는 의미입니다. opertator+, operator<< 등도 가능합니다.
		//
		//operator 우변에 const TaskQueue&처럼 참조 형식으로 만든 이유는 불필요한 복사 없이 값을 보는 것입니다. 특히, 값이 매우 크거나 mutex 같이 복사 불가능한 멤버가 있다면 문제가 발생합니다.
		//반환 타입(TaskQueue*)에 &를 붙힌 이유는 자기 자신을 반환할 때 또 다시 자기 자신을 복사한 임시 객체를 만들지 않기 위함입니다.
		//operator는 같은 타입을 검사한다고 했습니다. 우변에 TaskQueue라고 되어있다면 자연스럽게 좌측도 TaskQueue로 인식합니다.
		//
		//delete는 이 함수는 만들지도 말고, 누가 쓰려고 하면 컴파일 에러를 내라고 컴파일러에게 명령하는 것입니다.
		//mutex나 condition_variable 같은 것들은 복사가 불가능하기 때문에 TaskQueue끼리는 복사하지 못하게 합니다.
		TaskQueue& operator=(const TaskQueue&) = delete;

		//작업을 추가합니다.
		void Push(T item) {
			{
				// std::lock_guard는 클래스 템플릿(타입), <std::mutex>는 lock_guard가 어떤 타입의 자물쇠를 관리할지 결정하는 템플릿 인자, lock은 객체 이름, (mutex_)는 생성자 인자로 실제 잠글 자물쇠입니다.
				std::lock_guard<std::mutex> lock(mutex_);
				//push(item)을 하면 item의 데이터를 큐 내부에 복사하는 비용이 발생하지만 move를 이용하면 item의 힙 메모리 포인터나 문자열 버퍼의 주소만 큐 내부로 넘깁니다.
				queue_.push(std::move(item));
			}//괄호를 벗어나면 자물쇠가 풀립니다.
			//notify_one(): 자고 있는 스레드 중 하나만 깨우라는 신호를 줍니다.
			cv_.notify_one();
		}

		//작업을 꺼냅니다. 데이터가 올 때까지 대기(Blocking)
		std::optional<T> Pop() {
			std::unique_lock<std::mutex> lock(mutex_);

			//큐에 데이터가 생기거나, 종료 신호가 올 때까지 스레드를 재웁니다.
			cv_.wait(lock, [this]() {			// [this]() {...} 는 람다함수입니다. TaskQueue 객체가 자기 자신의 포인터를 람다 함수 안으로 넘겨주어 람다 함수에서도 클래스 멤버 변수에 접근할 수 있습니다.
				return !queue_.empty() || stopFlag_;
			});

			//께어났는데 종료 신호가 왔고 큐도 비어있다면 데이터가 없음을 반환합니다.
			if (stopFlag_ && queue_.empty()) {
				return std::nullopt;			//비어 있음을 의미합니다.
			}
			// 맨 앞 데이터를 꺼내서 반환합니다.
			T item = std::move(queue_.front()); //맨 앞 데이터의 소유권을 가져옵니다.
			queue_.pop();						//큐에서 맨 앞 칸을 지웁니다. 이를 위해서 소유권이 필요했습니다.
			return item;
		}
		/*
		std::lock_guard
		단순 스코프{} 단위 잠금, lock/unlock 수동제어 불가, condition_variable.wait() 불가, 즉시 잠금. 지연 잠금 불가, 소유권 이동 불가, 오버헤드 0.

		std::unique_lock
		중간 해제/조건 대기 등 복잡한 잠금 제어, 수동 lock/unlock 가능, condition_variable.wait() 가능, 지연 잠금 가능, 락 소유권 이동 가능, 미세한 오버헤드.
		*/

		//작업 큐 중지 및 대기 해제
		void Stop() {
			{
				std::lock_guard<std::mutex> lock(mutex_);
				stopFlag_ = true;
			}
			cv_.notify_all();
		}
		
		void Clear() {
			std::lock_guard<std::mutex> lock(mutex_);
			std::queue<T> emptyQueue;
			std::swap(queue_, emptyQueue);
		}
		
		size_t Size() const {
			//읽기 전용 함수지만, lock(mutex_)를 실행하는 순간 metex 내부의 상태가 열림에서 잠김으로 변합니다. 컴파일러는 읽기 전용인데 변수를 수정했다고 판단하여 에러를 발생시킵니다.
			//그러므로 위에서 mutex_에 mutable을 붙혀서 선언했습니다.
			std::lock_guard<std::mutex> lock(mutex_);
			return queue_.size();
		}

		bool IsEmpty() const {
			std::lock_guard<std::mutex> lock(mutex_);
			return queue_.empty();
		}
	};

	//WorkerManager
	class WorkerManager {
	private:
		//std::vector는 크기가 고정되지 않고 자유롭게 줄거나 늘어날 수 있습니다.
		//WinKernel::Process::WorkerProcess는 WinKernel.Process에서 가져온 윈도우 자식 프로세스 1개를 제어하는 객체입니다.
		std::vector<WinKernel::Process::WorkerProcess> workers_;
		DWORD maxWorkers_{ 0 };
	
	public:
		// 기본 생성자: 사용 가능한 H/W 논리 코어 수 감지
		WorkerManager() {
			unsigned int cores = std::thread::hardware_concurrency() - 2;

			//(cores>0) ? A:B 
			//조건식 ? 참일 때 값 : 거짓일 때 값
			//:4 예외 처리용 기본값. hardware_concurrency()가 코어 수 감지에 실패 시 0을 반환할 수 있습니다.
			//static_cast: 컴파일 타임에 상식적으로 이 변환이 가능한가를 검사하고 변환.
			maxWorkers_ = (cores > 0) ? static_cast<DWORD>(cores) : 4;
		}

		explicit WorkerManager(DWORD customWorkerCount) //explicit: 암시적으로 형변환을 하지 말고 개발자가 명시적으로 직접 적었을 때만 변환하라고 강제합니다.
			//WorkerManager wm = 4; -> 컴파일 에러. WorkerManager wm(4); 또는 WorkerManager wm = WorkerManager(4); 형태로 명시적 생성해야 합니다.
			: maxWorkers_(customWorkerCount) {
		}

		~WorkerManager() {
			StopAll();
		}

		//복사 방지
		WorkerManager(const WorkerManager&) = delete;
		WorkerManager& operator=(const WorkerManager&) = delete;

		//이동 허용 -> 복사 생성자를 =delete하면 컴파일러는 기본 이동 생성자를 자동 생성하지 않고 차단하기에 굳이 작성하는 것입니다.
		//&&는 우측값 참조입니다. =default는 컴파일러가 알아서 이동 코드를 만들라는 의미입니다.
		//noexcept는 이동하다가 예외처리를 하지 않음을 보장합니다.
		WorkerManager(WorkerManager&&) noexcept = default;
		WorkerManager& operator=(WorkerManager&&) noexcept = default;

		//지정된 개수만큼 워커 프로세스 일괄 실행
		bool InitializeAndLaunchAll(const wchar_t* targetBinaryPath) {
			workers_.clear();
			workers_.reserve(maxWorkers_);

			for (DWORD i = 0; i < maxWorkers_; ++i) {
				WinKernel::Process::WorkerProcess worker;

				if (worker.Launch(i + 1, targetBinaryPath)) {
					workers_.push_back(std::move(worker));
				}
				else {
					//일부 생성 실패 시 현재까지 실행된 것 정리 후 반환
					StopAll();
					return false;
				}
			}
			return true;
		}

		// 모든 워커 프로세스 즉시 종료 및 자원 정리
		void StopAll() {
			for (auto& worker : workers_) {
				if (worker.IsRunning()) {
					worker.Kill(0);
				}
				worker.Close();
			}
			workers_.clear();
		}

		//살아있는 워커 수 반환
		size_t GetActiveWorkerCount() const {
			size_t activeCount = 0;
			for (const auto& worker : workers_) {
				if (worker.IsRunning()) {
					activeCount++;
				}
			}
			return activeCount;
		}

		//특정 워커 상태 점검
		size_t GetTotalWorkerCount() const { return workers_.size(); }
		DWORD GetMaxWorkerLimit() const { return maxWorkers_; }

		//워커 백터 참조
		std::vector<WinKernel::Process::WorkerProcess>& GetWorkers() { return workers_; }
	};

}