/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import injectCustomCss from 'src/dashboard/util/injectCustomCss';

declare global {
  interface Window {
    __xss?: number;
  }
}

// eslint-disable-next-line no-restricted-globals -- TODO: Migrate from describe blocks
describe('injectCustomCss', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    document
      .querySelectorAll('.CssEditor-css')
      .forEach(element => element.remove());
    delete window.__xss;
  });

  test('applies css as text to a style element', () => {
    const css = '.foo { color: red; }';
    injectCustomCss(css);

    const style = document.querySelector('.CssEditor-css');
    expect(style).not.toBeNull();
    expect(style?.textContent).toBe(css);
  });

  test('assigns css via textContent and never via innerHTML', () => {
    // The core of the fix: user-authored CSS must be assigned as raw text
    // (textContent), which is not HTML-parsed, rather than via innerHTML
    // (CWE-79). jsdom treats <style> as a raw-text element, so parsing
    // behavior alone cannot distinguish the two APIs; we assert the
    // mechanism directly by instrumenting the created style element.
    const realCreateElement = document.createElement.bind(document);
    const innerHTMLSetter = jest.fn();
    let textContentValue: string | null = null;

    jest
      .spyOn(document, 'createElement')
      .mockImplementation((tagName: string) => {
        const element = realCreateElement(tagName);
        if (tagName === 'style') {
          Object.defineProperty(element, 'innerHTML', {
            configurable: true,
            get: () => textContentValue ?? '',
            set: innerHTMLSetter,
          });
          Object.defineProperty(element, 'textContent', {
            configurable: true,
            get: () => textContentValue,
            set: (value: string) => {
              textContentValue = value;
            },
          });
        }
        return element;
      });

    const css = '.foo { color: red; }';
    injectCustomCss(css);

    expect(innerHTMLSetter).not.toHaveBeenCalled();
    expect(textContentValue).toBe(css);
  });

  test('does not HTML-parse the css string (no markup injection)', () => {
    const css = '</style><img src=x onerror="window.__xss=1">';
    injectCustomCss(css);

    const style = document.querySelector('.CssEditor-css');
    expect(style).not.toBeNull();
    // No element node (e.g. <img>) should be created under the style element.
    expect(style?.children.length).toBe(0);
    expect(style?.querySelector('img')).toBeNull();
    expect(document.querySelector('img')).toBeNull();
    // The onerror handler must never fire.
    expect(window.__xss).toBeUndefined();
    // The malicious string is preserved verbatim as text, not parsed.
    expect(style?.textContent).toBe(css);
  });

  test('reuses the existing style element on subsequent calls', () => {
    injectCustomCss('.a { color: red; }');
    injectCustomCss('.b { color: blue; }');

    const styles = document.querySelectorAll('.CssEditor-css');
    expect(styles.length).toBe(1);
    expect(styles[0].textContent).toBe('.b { color: blue; }');
  });

  test('removeCustomCSS removes the injected style element', () => {
    const remove = injectCustomCss('.a { color: red; }');
    expect(document.querySelector('.CssEditor-css')).not.toBeNull();
    remove();
    expect(document.querySelector('.CssEditor-css')).toBeNull();
  });
});
