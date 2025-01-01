function handler() {
    let sent1 = parseInt(psutil.net_io_counters()[0]), recv1 = parseInt(psutil.net_io_counters()[1]);
    let cpu = parseFloat(psutil.cpu_percent(interval=1));
    let sent2 = parseInt(psutil.net_io_counters()[0]), recv2 = parseInt(psutil.net_io_counters()[1]);
    return [recv2 - recv1, sent2 - sent1, recv2, sent2, cpu]
}