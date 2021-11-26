from datetime import datetime
import enum
import os
from posixpath import dirname
import osquery
import yaml
import platform
import os
import json
import glob
import shutil
import logging
import subprocess
import argparse
import zipfile
import shutil
import time
import gzip
import re


class JSONFormatter(logging.Formatter):
    def __init__(self,output_format):
        if output_format == "json":
            JSON_LOGGER_FORMAT = '{"time":"%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
        else:
            JSON_LOGGER_FORMAT = '{"Data":{"@timestamp":"%(asctime)s", "level": "%(levelname)s", "message": %(message)s}, "data_type": "osqueryIR_log", "data_source": "osqueryIR_log", "data_path": "osqueryIR_log"}'
        super().__init__(JSON_LOGGER_FORMAT, datefmt="%Y-%m-%dT%H:%M:%SZ")
    def format(self, record):
        record.msg = json.dumps(record.msg)
        return super().format(record)

def epoch_to_iso(timestamp):
    timestamp = int(timestamp)
    import datetime;
    return datetime.datetime.fromtimestamp(timestamp).isoformat()

def time_without_year_to_iso(time):
    current_year = datetime.now().year
    log_time = f'{current_year} {time}'
    log_fulltime = datetime.strptime(log_time,"%Y %b %d %H:%M:%S")
    if log_fulltime < datetime.now():
        return log_fulltime.isoformat()
    else:
        log_time = f'{current_year - 1} {time}'
        log_fulltime = datetime.strptime(log_time,"%Y %b %d %H:%M:%S")
        return log_fulltime.isoformat()

def nginx_time_to_iso(timestamp):
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").strftime("%Y-%m-%dT%H:%M:%S")

def cleanup(paths):
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)

def compress(src_path, dest_path):
    zip_file = zipfile.ZipFile(dest_path, "w")
    for dirname, subdirs, files in os.walk(src_path):
        zip_file.write(dirname)
        for filename in files:
            zip_file.write(os.path.join(dirname, filename))
    zip_file.close()

def map(record, maps):
    for map in maps:
        value = record.pop(map["name"])
        if map.get("modifier"):
            if map.get("modifier") == "epoch_to_iso":
                record[map["map_to"]] = epoch_to_iso(value)
            elif map.get("modifier") == "time_without_year_to_iso":
                record[map["map_to"]] = time_without_year_to_iso(value)
            elif map.get("modifier") == "nginx_time_to_iso":
                record[map["map_to"]] = nginx_time_to_iso(value)
            else:
                record[map["map_to"]] = value

        else:
            record[map["map_to"]] = value
    return record

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A Linux artifact collection tool')
    parser.add_argument('--osquery-binary', help='osqueryd binary path (Default=./osqueryd)', default="./osqueryd")
    parser.add_argument('-c', '--config', help='Path to the configuration file (Default=./config.yaml)', default="./config.yaml")
    parser.add_argument('-o', '--output', help='Change the output folder name (Defaults to the machine hostname)', default=platform.node())
    parser.add_argument('-q','--quiet', help='Do not print log messages', action='store_true', default=False)
    parser.add_argument('--log-file-name', help='Name of the log file (Default=osqueryIR_log)', default="osqueryIR_log")
    parser.add_argument('--log-level', help='Set logging level (Default=INFO)', default="INFO", choices=["CRITICAL","ERROR","WARNING","INFO","DEBUG"])
    parser.add_argument('--output-format', help='Change the output format (Default=jsonl)', default="jsonl", choices=["jsonl","kjson"])
    parser.add_argument('--disable-collect', help='Disable collection artifacts', action="store_true", default=False)
    args = parser.parse_args()
    
    # Spawn an osquery process using an ephemeral extension socket.
    instance = osquery.SpawnInstance(args.osquery_binary)
    instance.open()  # This may raise an exception
    dir_name = args.output
    config = yaml.load(open(args.config,'r'), Loader=yaml.FullLoader)
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    LOGGER_FORMAT = '%(asctime)-15s %(levelname)s: %(message)s'

    logging.Formatter.converter = time.gmtime
    logger = logging.getLogger('osqueryIR')
    file_handler = logging.FileHandler(f"{dir_name}/{args.log_file_name}.{args.output_format}")
    file_handler.setFormatter(JSONFormatter(args.output_format))
    logger.setLevel(args.log_level)
    logger.addHandler(file_handler)
    s_time = time.time()
    logger.info(f'osqueryIR started')
    if not args.quiet:
        logFormatter = logging.Formatter(LOGGER_FORMAT)
        console_log  = logging.StreamHandler()
        console_log.setFormatter(logFormatter)
        logger.addHandler(console_log)
    for artifact in config['artifacts']:
        key = list(artifact.keys())[0]
        if args.output_format == "jsonl":
            output_file = f'{key}.jsonl'
        else:
            output_file = f'{key}.kjson'
        logger.info(f'Gatharing the artifact "{key}"')
        if artifact.get(key).get('queries'):
            # Issues queries and call osquery Thrift APIs.
            with open(os.path.join(dir_name, output_file),'w') as outfile:
                for query in artifact.get(key).get('queries'):
                    logger.info(f'Executing the query "{query}" for the artifact "{key}"')
                    try:
                        results = instance.client.query(query)
                    except Exception as e:
                        logger.error(f'Executing the query "{query}" for the artifact "{key}", ERROR: {e}')
                        instance = osquery.SpawnInstance(args.osquery_binary)
                        instance.open()
                    for row in results.response:
                        if artifact.get(key).get('maps'):
                            row = map(row,artifact.get(key).get('maps'))

                        if args.output_format == "jsonl":
                            outfile.write(json.dumps(row))
                            outfile.write('\n')
                        elif args.output_format == "kjson":
                            results = {}
                            results["Data"] = row
                            results["data_type"] = key
                            results["data_source"] = key
                            results["data_path"] = os.path.join(dir_name, output_file)
                            
                            outfile.write(json.dumps(results))
                            outfile.write('\n')

        if artifact.get(key).get('collect'):
            if not args.disable_collect:
                for path in artifact.get(key).get('collect'):
                    for src_path in glob.glob(path, recursive=True):
                        if os.path.isfile(src_path):
                            fullpath = os.path.join(dir_name, key) + src_path
                            logger.info(f'Copying the file "{src_path}" to "{fullpath}" for the artifact "{key}"')
                            dest_path = os.path.dirname(fullpath)
                            try:
                                os.makedirs(dest_path)
                            except Exception as e:
                                logger.error(f'Error creating the directories "{dest_path}" for the artifact "{key}", ERROR: {e}')
                            try:
                                shutil.copyfile(src_path, fullpath)
                            except Exception as e:
                                logger.error(f'Copying the file "{src_path}" to "{fullpath}" for the artifact "{key}", ERROR: {e}')
        if artifact.get(key).get('command'):
            results = []
            with open(os.path.join(dir_name, output_file),'w') as outfile:
                for command in artifact.get(key).get('command'):
                    logger.info(f'Executing the command "{command}" for the artifact "{key}"')
                    command_res = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    data = command_res.stdout.read()
                    if data:
                        for i, line in enumerate(data.decode('utf-8').split('\n')):
                            if line != "":
                                res = {}
                                res['command'] = command
                                res['line'] = i
                                res['stdout'] = line
                                res['stderr'] = command_res.stderr.read().decode('utf-8')
                                if args.output_format == "jsonl":
                                    outfile.write(json.dumps(res))
                                    outfile.write('\n')
                                elif args.output_format == "kjson":
                                    kjson = {}
                                    kjson["Data"] = res
                                    kjson["data_type"] = key
                                    kjson["data_source"] = key
                                    kjson["data_path"] = os.path.join(dir_name, output_file)
                                    
                                    outfile.write(json.dumps(kjson))
                                    outfile.write('\n')
                    else:
                        for i, line in enumerate(command_res.stderr.read().decode('utf-8').split('\n')):
                            res = {}
                            res['command'] = command
                            res['line'] = i
                            res['stdout'] = None
                            res['stderr'] = line
                            if args.output_format == "jsonl":
                                outfile.write(json.dumps(res))
                                outfile.write('\n')
                            elif args.output_format == "kjson":
                                kjson = {}
                                kjson["Data"] = res
                                kjson["data_type"] = key
                                kjson["data_source"] = key
                                kjson["data_path"] = os.path.join(dir_name, output_file)
                                outfile.write(json.dumps(kjson))
                                outfile.write('\n')
                                
        if artifact.get(key).get('parse'):
            with open(os.path.join(dir_name, output_file),'w') as outfile:
                art = artifact.get(key).get('parse')
                try:
                    for path in glob.glob(art["path"]):
                        logger.info(f"Parsing the log file {path} for the artifact {key}")
                        log_file = gzip.open(path, 'r') if '.gz' in path else open(path, 'r')
                        for line in log_file:
                            try:
                                if isinstance(line,bytes):
                                    line = line.decode("latin")
                                line = line.replace("\n","").replace("\r","")
                                m = re.search(art["regex"],line)
                                results = {}
                                for i,field in enumerate(art["fields"]):
                                    results.update({field: m.groups()[i]})

                                if artifact.get(key).get('maps'):
                                    results = map(results,artifact.get(key).get('maps'))

                                if args.output_format == "jsonl":
                                    outfile.write(json.dumps(results))
                                    outfile.write('\n')
                                elif args.output_format == "kjson":
                                    kjson = {}
                                    kjson["Data"] = results
                                    kjson["data_type"] = key
                                    kjson["data_source"] = key
                                    kjson["data_path"] = path
                                    outfile.write(json.dumps(kjson))
                                    outfile.write('\n')
                                    
                            except Exception as e:
                                logger.error(f'Error parsing the line "{line}" for the artifact "{key}" in the log file {path}, ERROR: {e}')
                except Exception as e:
                    logger.error(f'Error opening the file/s {path} for the artifact "{key}", ERROR: {e}')


        



    logger.info(f'osqueryIR finished in "{time.time() - s_time}" seconds')
    compress(dir_name, f'{args.output}.zip')
    # socket_name = instance._socket[1]
    # del(instance)
    cleanup([dir_name,instance._socket[1]])
