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
import injectCustomCss from './injectCustomCss';

const CLASS_NAME = 'CssEditor-css';

afterEach(() => {
  document
    .querySelectorAll(`.${CLASS_NAME}`)
    .forEach(element => element.remove());
  delete (window as unknown as { __xss?: number }).__xss;
});

test('injects the provided CSS as text content of the style element', () => {
  injectCustomCss('.foo { color: red; }');
  const style = document.querySelector(`.${CLASS_NAME}`) as HTMLStyleElement;
  expect(style).not.toBeNull();
  expect(style.textContent).toBe('.foo { color: red; }');
});

test('does not HTML-parse the CSS string into element nodes (XSS-safe)', () => {
  injectCustomCss('</style><img src=x onerror="window.__xss=1">');
  const style = document.querySelector(`.${CLASS_NAME}`) as HTMLStyleElement;
  expect(style).not.toBeNull();
  expect(style.querySelector('img')).toBeNull();
  expect(style.children).toHaveLength(0);
  expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
});

test('returns a cleanup function that removes the style element', () => {
  const remove = injectCustomCss('.foo { color: red; }');
  expect(document.querySelector(`.${CLASS_NAME}`)).not.toBeNull();
  remove();
  expect(document.querySelector(`.${CLASS_NAME}`)).toBeNull();
});
