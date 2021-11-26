# osqueryIR

osqueryIR is an artifact collection tool for Linux systems. It provides the following capabilities:

* Execute osquery SQL queries
* Collect files and folder
* Execute system commands
* Parse log files (ex. nginx, auth, syslog, etc) using regex

## Try it

1. Clone this repo

   ```bash
   git clone https://github.com/abdulrhmanalfaifi/osqueryIR
   ```

2. Download python dependencies

   ```bash
   python3 -m pip install -r requirments.txt
   ```

3. Try it using this command

   ```bash
   python3 osqueryIR.py -h
   ```

## Usage

The following is the help message for osqueryIR:

```bash
usage: osqueryIR.py [-h] [--osquery-binary OSQUERY_BINARY] [-c CONFIG]
                    [-o OUTPUT] [-q] [--log-file-name LOG_FILE_NAME]
                    [--log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
                    [--output-format {jsonl,kjson}] [--disable-collect]

A Linux artifact collection tool

optional arguments:
  -h, --help            show this help message and exit
  --osquery-binary OSQUERY_BINARY
                        osqueryd binary path (Default=./osqueryd)
  -c CONFIG, --config CONFIG
                        Path to the configuration file (Default=./config.yaml)
  -o OUTPUT, --output OUTPUT
                        Change the output folder name (Defaults to the machine
                        hostname)
  -q, --quiet           Do not print log messages
  --log-file-name LOG_FILE_NAME
                        Name of the log file (Default=osqueryIR_log)
  --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set logging level (Default=INFO)
  --output-format {jsonl,kjson}
                        Change the output format (Default=jsonl)
  --disable-collect     Disable collection artifacts
```

* `--osquery-binary`: osqueryd binary path. By default it will uses the binary in this repo.
* `-c` or `--config`: path to osqueryIR configuration. By default it will be `config.yaml` in this repo.
* `-o` or `--output`: the output file (zip file) name, By default it will be the machine hostname.
* `-q` or `--quit`: Do not print logging to the stdout. osqueryIR will always write the log to the output file.
* `--log-file-name`: change the default name for the log file (osqueryIR_log).
* `--log-level`: the log level, default is `INFO`.
* `--output-format`: osqueryIR support writing the results in two different formats:
  * jsonl: a newline separated JSON object. Each object represent a record.
  * kjson: the format understood by Kuiper. If you are planing to use Kuiper for analysis then you should use this format.

* `--disable-collect`: disable artifact collecting. Only parsing and osquery artifacts will be acquired.

## Configuration

osqueryIR accepts a configuration file that contains artifact specification. The following is an example configuration along with comments:

```yaml
artifacts:  
    # Name of artifact. the results will be saved to a file with this name
  - logged_in_users:
      # artifact type. queries run osquery SQL queries and return the results as json
      queries:
        - 'select * from logged_in_users'
      # Optional: map the field called `name` to `@timestamp` and run the modfier `epoch_to_iso` on the value. `modifier` field is not required
      maps:
        - name: time
          map_to: '@timestamp'
          modifier: epoch_to_iso
      # Optional: description of the artifact
      description: 'Collect and parse the currently loggedin users'
  - logs:
      # artifact type. collect the specified files and directories without parsing
      collect:
        - '/var/log/**'
        - '/home/*/.vnc/*.log'
      description: 'Collect logs wellknow paths'
  - auth_log:
      # artifact type. parse the specified files using regex and return the results as json.
      parse:
        # files to parse
        path: '/var/log/auth.log*'
        # regex used for parsing
        regex: '([A-Z][a-z]{2}[ ]{1,}[0-9]{1,2}[ ]{1,2}[0-9]{1,2}:[0-9]{2}:[0-9]{2}) ([a-zA-Z0-9_\-]+) ([a-zA-Z0-9_\-\]\(\)=\./]+)\[?([0-9]+)?\]?: (.*)'
        # the name of the extracted fields
        fields:
          - 'time'
          - 'hostname'
          - 'service'
          - 'pid'
          - 'msg'
      maps:
        - name: time
          map_to: '@timestamp'
          modifier: time_without_year_to_iso
      description: 'Parse auth logs from the path /var/log/, and return the results as jsonl/kjson'
  - bad_logins:
  	  # artifact type. Execute system command and return stdout & stderr
      command:
        - 'lastb'
```

## Example

To collect the artifacts from the provided configurations, execute the following command:

```bash
python3 osqueryIR.py
```

A file will be created named `{HOSTNAME}.zip` that contains all artifacts.

## Useing osqueryIR with Kuiper

osqueryIR can generate the result in `kjson` format which could be ingested by Kuiper. To collect artifacts in `kjson` format execute the following command:

```bash
python3 osqueryIR.py --output-format kjson --disable-collect
```

upload the file to Kuiper and execute the `kjson` parser

![osqueryIR_Kuiper](./screenshots/osqueryIR_Kuiper.gif)