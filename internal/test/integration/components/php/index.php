<?php
    $MB = 1024*1024;
    $size = intval($_ENV['PHP_MEM_USED_IN_MB']) * $MB;
    $memoryUsed = str_repeat('a', $size);

    sleep(intval($_ENV['PHP_EXECUTION_TIME_IN_SECONDS']));
    echo "PHP script completed\n";
    error_log("PHP script completed");
?>
