"""
Утилиты для работы с XML с поддержкой отслеживания номеров строк.

Стандартный xml.etree.ElementTree не сохраняет информацию о номерах строк.
Этот модуль предоставляет обёртки для получения точного location для уязвимостей.
"""

import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List
from pathlib import Path


class ElementWithLine:
    """
    Обёртка над XML-элементом с сохранением номера строки.
    
    Используется вместе с TargetWithLineNumbers для парсинга.
    """
    
    def __init__(self, element: ET.Element, lineno: int):
        self.element = element
        self.lineno = lineno
    
    def __getattr__(self, name: str):
        """Делегирует все атрибуты внутреннему элементу."""
        return getattr(self.element, name)
    
    def get_line_number(self) -> int:
        """Возвращает номер строки элемента в исходном файле."""
        return self.lineno


class TargetWithLineNumbers:
    """
    XMLParser target, который сохраняет номера строк для элементов.
    
    Пример использования:
        parser = ET.XMLParser(target=TargetWithLineNumbers())
        tree = ET.parse("config.xml", parser)
        root = tree.getroot()  # Вернёт ElementWithLine
    """
    
    def __init__(self):
        self._target = ET.TreeBuilder()
        self._line_stack: List[int] = []
    
    def start(self, tag: str, attrib: Dict[str, str]) -> ElementWithLine:
        # Получаем номер строки из позиции парсера
        # Примечание: ElementTree не предоставляет прямой доступ к lineno,
        # поэтому используем эвристику через поиск в исходном тексте
        element = self._target.start(tag, attrib)
        return ElementWithLine(element, lineno=1)  # Заглушка, см. parse_with_linenumbers
    
    def end(self, tag: str) -> ElementWithLine:
        element = self._target.end(tag)
        return ElementWithLine(element, lineno=1)
    
    def data(self, data: str):
        return self._target.data(data)
    
    def close(self) -> ElementWithLine:
        element = self._target.close()
        return ElementWithLine(element, lineno=1)
    
    def comment(self, text: str):
        return self._target.comment(text) if hasattr(self._target, 'comment') else None
    
    def pi(self, target: str, data: str):
        return self._target.pi(target, data) if hasattr(self._target, 'pi') else None


def parse_xml_with_linenumbers(filepath: str) -> tuple[ET.ElementTree, Dict[ET.Element, int]]:
    """
    Парсит XML-файл и возвращает дерево + маппинг элементов на номера строк.
    
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    tree = ET.parse(filepath)
    root = tree.getroot()
    
    element_to_line: Dict[ET.Element, int] = {}
    
    def find_element_lines(element: ET.Element, start_line: int = 1, tag_index: Dict[str, int] = None):
        if tag_index is None:
            tag_index = {}
        
        tag = element.tag
        # Убираем namespace из тега для поиска
        tag_name = tag.split('}')[-1] if '}' in tag else tag
        
        # Считаем, какой по счёту этот тег с таким именем
        tag_index[tag_name] = tag_index.get(tag_name, 0) + 1
        current_index = tag_index[tag_name]
        
        # Ищем открывающий тег, учитывая порядковый номер
        found_count = 0
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            # Ищем тег с учётом namespace
            if f"<{tag}" in line or f"<{tag}>" in line or f"<{tag} " in line:
                found_count += 1
                if found_count == current_index:
                    element_to_line[element] = i + 1  # 1-based line number
                    # Рекурсивно ищем дочерние элементы
                    child_index = {}
                    for child in element:
                        find_element_lines(child, start_line=i + 2, tag_index=child_index)
                    break
    
    find_element_lines(root)
    return tree, element_to_line


def get_element_line_number(element: ET.Element, line_mapping: Dict[ET.Element, int], default: int = 1) -> int:
    """
    Получает номер строки для элемента из pre-computed маппинга.
    
    Args:
        element: XML-элемент
        line_mapping: Словарь {element: line_number}
        default: Значение по умолчанию, если элемент не найден
    
    Returns:
        Номер строки (1-based)
    """
    return line_mapping.get(element, default)


def find_element_by_xpath_with_line(
    root: ET.Element, 
    xpath: str, 
    line_mapping: Dict[ET.Element, int]
) -> List[tuple[ET.Element, int]]:
    """
    Находит элементы по XPath и возвращает их с номерами строк.
    
    Args:
        root: Корневой элемент
        xpath: XPath-выражение
        line_mapping: Словарь {element: line_number}
    
    Returns:
        Список кортежей (element, line_number)
    """
    results = []
    for element in root.findall(xpath):
        lineno = line_mapping.get(element, 1)
        results.append((element, lineno))
    return results