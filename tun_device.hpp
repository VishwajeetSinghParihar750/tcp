#pragma once
#include "logger.hpp"
#include <stdexcept>
#include <string>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

class tun_device
{
public:
    explicit tun_device(const std::string &name = "mytun",
                        const std::string &ip_cidr = "10.69.0.1/24",
                        const std::string &route_cidr = "10.69.0.0/24")
        : tun_name_(name), ip_cidr_(ip_cidr), route_cidr_(route_cidr)
    {
        std::signal(SIGINT, [](int)
                    { std::exit(0); }); // so just call normal exit and with it its hadnler

        tun_fd_ = createTun();
        configureTun();
    }

    tun_device(const tun_device &) = delete;
    tun_device &operator=(const tun_device &) = delete;
    tun_device(tun_device &&) = delete;
    tun_device &operator=(tun_device &&) = delete;

    ~tun_device()
    {
        cleanup();
    }

    int fd() const { return tun_fd_; }
    std::string name() const { return tun_name_; }

private:
    int tun_fd_ = -1;
    std::string tun_name_;
    std::string ip_cidr_;
    std::string route_cidr_;

    int createTun()
    {
        int fd = open("/dev/net/tun", O_RDWR);
        if (fd < 0)
            throw std::runtime_error("Failed to open /dev/net/tun: " + std::string(strerror(errno)));

        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, tun_name_.c_str(), IFNAMSIZ - 1);

        if (ioctl(fd, TUNSETIFF, reinterpret_cast<void *>(&ifr)) < 0)
        {
            close(fd);
            throw std::runtime_error("ioctl(TUNSETIFF) failed: " + std::string(strerror(errno)));
        }

        tun_name_ = ifr.ifr_name;
        logger::getInstance().logInfo("Created TUN device: " + tun_name_);
        return fd;
    }

    void runCommandChecked(const std::string &cmd, const std::string &errmsg)
    {
        int ret = system(cmd.c_str());
        if (ret != 0)
            throw std::runtime_error(errmsg + " (command: " + cmd + ")");
    }

    void configureTun()
    {
        runCommandChecked("sudo ip addr add " + ip_cidr_ + " dev " + tun_name_,
                          "Failed to assign IP to TUN");
        runCommandChecked("sudo ip link set dev " + tun_name_ + " up",
                          "Failed to bring TUN up");
        runCommandChecked("sudo ip route replace " + route_cidr_ + " dev " + tun_name_,
                          "Failed to add route for TUN");
    }

    void cleanup()
    {
        if (tun_fd_ >= 0)
        {
            close(tun_fd_);
            tun_fd_ = -1;
        }

        auto run_cmd = [](const std::string &cmd) // not throwing coz in destructor
        {
            int ret = system(cmd.c_str());
            if (ret != 0)
                logger::getInstance().logError("Command failed: ", cmd);
        };

        run_cmd("sudo ip route del " + route_cidr_ + " dev " + tun_name_);
        run_cmd("sudo ip link set dev " + tun_name_ + " down");
        run_cmd("sudo ip addr del " + ip_cidr_ + " dev " + tun_name_);

        logger::getInstance().logInfo("TUN device cleaned up");
    }
};
