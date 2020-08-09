import gitlab
import requests
from base64 import b64decode
import ntpath
from njsscan.njsscan import NJSScan
from sys import exit
from os.path import isfile
from loguru import logger
import json

# CI_MERGE_REQUEST_ID, CI_MERGE_REQUEST_PROJECT_ID

def get_pr_results(ci_token, project_id, branch, hash):
    gl = gitlab.Gitlab('https://www.gitlab.com', private_token=ci_token)
    project = gl.projects.get(project_id)
    commit = project.commits.get(hash)
    diff = commit.diff()
    file_list = []
    vul_list = []
    for single in diff:
        path = single.get('new_path')
        basename = ntpath.basename(path)
        if basename.endswith('.js'):
            url = "https://www.gitlab.com/api/v4/projects/{}/repository/files/{}?ref={}".format(project_id, path, branch)
            r = requests.get(url, headers={"PRIVATE-TOKEN": ci_token})
            content = b64decode(r.json().get('content').encode()).decode()
            with open(basename, 'w') as myfile:
                myfile.write(content)
            file_list.append(basename)
    if file_list:
        scanner = NJSScan(file_list, json=True, check_controls=False)
        results = scanner.scan()
        if 'nodejs' in results and results.get('nodejs'):
            sast = results.get('nodejs')
            for vname, vdict in sast.items():
                vul_dict = {
                    "name": vname,
                    "description": vdict.get('metadata').get('description')
                }
                cwe = str(vdict.get('metadata').get(
                    'cwe')).split(":")[0].split("-")[1]
                evidences = []
                files = vdict.get('files')
                for single_file in files:
                    single_evid = {
                        "url": single_file.get("file_path"),
                        "line_number": single_file.get('match_lines')[0],
                        "log": single_file.get('match_string')
                    }
                    evidences.append(single_evid)
                vul_dict['cwe'] = int(cwe)
                vul_dict['evidences'] = evidences
                vul_list.append(vul_dict)
    else:
        logger.info("No scoped files to scan")

    logger.info("successfully scanned PR for vulnerabilities")
    return vul_list


def write_to_pr(ci_token, project_id, mr_id, vul_dict):
    gl = gitlab.Gitlab('https://www.gitlab.com', private_token=ci_token)
    project = gl.projects.get(project_id)
    mdlist = []
    mr = project.mergerequests.get(mr_id)
    mdh1 = "## Review - Static Analysis - NodeJSScan\n\n"
    mdtable = "| Issue | File | Line | Confidence | Nature | Description | CWE |\n"
    mdheader = "|-------|:----------:|------:|------:|------:|------:|------:|\n"
    mdlist.append(mdh1)
    mdlist.append(mdtable)
    mdlist.append(mdheader)
    for single in vul_dict:
        name = single.get('name')
        desc = single.get('description')
        cwe = single.get('cwe', 0)
        if 'evidences' in single and single.get('evidences'):
            for single_evid in single.get('evidences'):
                mdlist.append('| {} | {} | {} | {} | {} | {} | {} |\n'.format(
                    name, 
                    single_evid.get('url'), 
                    single_evid.get('line_number'), 
                    "High",
                    "Security Finding",
                    desc,
                    cwe
                ))
    
    final_md = "".join(mdlist)
    mr.notes.create({'body': final_md})




# variables required are: 
#   * Gitlab CI Token
#   * ref (branch)
#   * project_id
#   * Hash (small Hash)


def main():
    if not isfile('config.json'):
        logger.error("Unable to find config json file. Exiting...")
        exit(1)
    else:
        with open('config.json') as jfile:
            config = json.loads(jfile.read())
        if not all(key in config for key in ('token', 'branch', 'project_id', 'hash')):
            logger.error('mandatory config parameters not present in config object')
            exit(1)
        else:
            try:
                results = get_pr_results(
                    config.get('token'),
                    config.get('project_id'),
                    config.get('branch'),
                    config.get('hash')
                )
                if results:
                    write_to_pr(
                        config.get('token'),
                        config.get('project_id'),
                        config.get('pr_id'),
                        results
                    )
            except Exception as e:
                logger.exception(e)
                exit(1)