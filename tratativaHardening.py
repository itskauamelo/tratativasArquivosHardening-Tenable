import os
import pandas as pd
import re
def process_csv_files(controls_file):
   with open(controls_file, 'r') as file:
       controls_to_keep = [line.strip() for line in file.readlines()]
   failed_count = 0
   passed_count = 0
   for filename in os.listdir():
       if filename.endswith('.csv'):
           try:
               df = pd.read_csv(filename, sep=',', encoding='utf-8', on_bad_lines='skip')
               required_columns = ['Plugin Name', 'Severity', 'DNS Name', 'Plugin Output', 'Description']
               ip_columns = ['IP Address', 'IP']
               present_ip_column = next((col for col in ip_columns if col in df.columns), None)
               netbios_column = 'NetBIOS Name' if 'NetBIOS Name' in df.columns else None
               if not present_ip_column:
                   print(f"Arquivo {filename} não contém nenhuma das colunas de IP necessárias.")
                   continue
               required_columns.append(present_ip_column)
               if netbios_column:
                   required_columns.append(netbios_column)
               if not all(column in df.columns for column in required_columns):
                   print(f"Arquivo {filename} não contém todas as colunas necessárias.")
                   continue
               actual_values = []
               results = []
               see_alsos = []
               for index, row in df.iterrows():
                   actual_value, result, see_also = '', '', ''
                   for column in ['Plugin Output', 'Description']:
                       if column in df.columns:
                           content = str(row[column])  # Converter para string
                           if column == 'Description':
                               actual_value_match = re.search(r'Actual Value: (.*?)\n', content, re.DOTALL)
                               result_match = re.search(r'\[(.*?)\]', content, re.DOTALL)
                               see_also_match = re.search(r'See Also: (.*)', content, re.DOTALL)
                           else:  # Plugin Output
                               actual_value_match = re.search(r'Actual Value: (.*?)\n', content, re.DOTALL)
                               result_match = re.search(r'Result: (.*?)\n', content, re.DOTALL)
                               see_also_match = re.search(r'See Also: (.*)', content, re.DOTALL)
                           if actual_value_match:
                               actual_value = actual_value_match.group(1).strip()
                           if result_match:
                               result = result_match.group(1).strip()
                           if see_also_match:
                               see_also = see_also_match.group(1).strip()
                               if see_also.startswith('Reference'):
                                   see_also = ''
                           break
                   actual_values.append(actual_value)
                   results.append(result)
                   see_alsos.append(see_also)
               df['Actual Value'] = actual_values
               df['Result'] = results
               df['See Also'] = see_alsos
               if 'Plugin Family' in df.columns:
                   df_filtered = df[
                       df['Plugin Name'].isin(controls_to_keep) |
                       df['Description'].str.contains('|'.join(controls_to_keep), na=False)
                   ]
                   # Aplica os critérios para Description
                   for index, row in df_filtered.iterrows():
                       content = str(row['Description'])
                       result_match = re.search(r'\[(.*?)\]', content, re.DOTALL)
                       actual_value_match = re.search(r'Actual Value: (.*?)\n', content, re.DOTALL)
                       see_also_match = re.search(r'See Also: (.*)', content, re.DOTALL)
                       if result_match:
                           df_filtered.at[index, 'Result'] = result_match.group(1).strip()
                       if actual_value_match:
                           df_filtered.at[index, 'Actual Value'] = actual_value_match.group(1).strip()
                       if see_also_match:
                           see_also = see_also_match.group(1).strip()
                           if see_also.startswith('Reference'):
                               see_also = ''
                           df_filtered.at[index, 'See Also'] = see_also
               else:
                   df_filtered = df[
                       df['Plugin Name'].isin(controls_to_keep) |
                       df['Plugin Output'].str.contains('|'.join(controls_to_keep), na=False)
                   ]
               if df_filtered.empty:
                   print(f"Arquivo {filename} não contém dados relevantes após o filtro.")
                   continue
               df_filtered = df_filtered[required_columns + ['Actual Value', 'Result', 'See Also']]
               output_file = f"{os.path.splitext(filename)[0]}.xlsx"
               df_filtered.to_excel(output_file, index=False)
               print(f"Os dados processados foram salvos em {output_file}")
               # Contabiliza os resultados
               failed_count += df_filtered['Result'].str.contains('FAILED', case=False).sum()
               passed_count += df_filtered['Result'].str.contains('PASSED', case=False).sum()
               # Remove o CSV após o processamento
               os.remove(filename)
               print(f"Arquivo {filename} removido.")
           except pd.errors.ParserError as e:
               print(f"Erro ao processar o arquivo {filename}: {e}")
   with open('Result.txt','w') as out:
    out.write(f"Total de resultados FAILED: {failed_count}\n")
    out.write(f"Total de resultados PASSED: {passed_count}\n")
controls_file = 'controles.txt'
process_csv_files(controls_file)